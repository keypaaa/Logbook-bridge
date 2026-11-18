import os
import re
import json
import base64
import urllib3
from datetime import datetime, timedelta
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from exchangelib import Credentials, Account, Configuration, DELEGATE, FileAttachment

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

MAX_PDF_SIZE_BYTES = 25 * 1024 * 1024
MERIDIAN_BASE_URL = "https://faps.uzairways.com/web.meridian"

MONTH_PREFIXES = [
    ('янв', 0),
    ('фев', 1),
    ('мар', 2),
    ('апр', 3),
    ('май', 4), ('мая', 4), ('мае', 4),
    ('июн', 5),
    ('июл', 6),
    ('авг', 7),
    ('сен', 8),
    ('окт', 9),
    ('ноя', 10),
    ('дек', 11)
]

RU_MONTH_NAMES = {
    1: 'январь', 2: 'февраль', 3: 'март', 4: 'апрель',
    5: 'май', 6: 'июнь', 7: 'июль', 8: 'август',
    9: 'сентябрь', 10: 'октябрь', 11: 'ноябрь', 12: 'декабрь'
}

def is_trusted_sender(item):
    sender = getattr(item, 'sender', None)
    if not sender:
        return True
    sender_email = (getattr(sender, 'email_address', '') or '').strip().lower()
    if '@' in sender_email and not sender_email.endswith('@uzairways.com'):
        return False
    return True

def is_valid_pdf_attachment(attachment):
    if not isinstance(attachment, FileAttachment):
        return False
    name = (attachment.name or '').lower()
    if not name.endswith('.pdf'):
        return False
    content = attachment.content
    if not content or len(content) > MAX_PDF_SIZE_BYTES:
        return False
    if b'%PDF-' not in content[:1024]:
        return False
    return True

def is_payslip_email(item):
    subj = (getattr(item, 'subject', '') or '').lower().replace('ё', 'е')
    sender = getattr(item, 'sender', None)
    sender_name = (getattr(sender, 'name', '') or '').lower() if sender else ''
    sender_email = (getattr(sender, 'email_address', '') or '').lower() if sender else ''

    if 'расчетный листок' in subj or 'расчетный лист' in subj:
        return True
    if 'salary.srv' in sender_name or 'salary.srv' in sender_email:
        return True
    return False

def is_flight_report_email(item, subject_filter):
    subj = (getattr(item, 'subject', '') or '').lower().replace('ё', 'е')
    return (subject_filter in subj or 'полетное задание' in subj or 'flight activities' in subj)

def extract_payslip_month_info(text_str):
    if not text_str:
        return None, None
    s = text_str.lower().replace('ё', 'е')
    year_match = re.search(r'\b(20\d{2})\b', s)
    if not year_match:
        return None, None
    year = int(year_match.group(1))

    for prefix, m_idx in MONTH_PREFIXES:
        if re.search(r'(?:^|[\s\.\(\)\-_])' + prefix, s):
            month_key = f"{year}_{m_idx}"
            yyyy_mm = f"{year}-{m_idx + 1:02d}"
            return month_key, yyyy_mm

    return None, None


# ==============================================================================
# КЛИЕНТ WEB MERIDIAN (ZK 10.2.1 AU ПРОТОКОЛ ДЛЯ WORKPLAN И PERSONAL FLIGHT TIME)
# ==============================================================================

def normalize_zk_text(text):
    """Декодирует \\\\uXXXX, \\uXXXX, \\xXX, \\' и \\/ в ответах ZK zkmx и zkau."""
    if not text:
        return ""
    s = re.sub(r'\\\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
    s = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)
    s = s.replace(r'\/', '/').replace(r"\'", "'").replace(r'\"', '"')
    return s

def extract_zk_dtid_and_prefix(raw_text):
    text = normalize_zk_text(raw_text)
    dtid = None
    # Варианты dtid в ZK 7/8/9/10: dt:'z_...', "dt":"z_...", zkau/view/z_...
    for pat in [
        r"['\"]?dt['\"]?\s*:\s*['\"]([^'\"]+)['\"]",
        r"/zkau/view/([^/\"']+)/",
        r"dtid\s*[=:]\s*['\"]([^'\"]+)['\"]"
    ]:
        m = re.search(pat, text)
        if m:
            dtid = m.group(1)
            break

    prefix = None
    for p_pat in [
        r"zkmx\(\s*\[\s*\d+\s*,\s*['\"]([a-zA-Z0-9_]{4})[a-zA-Z0-9_]*['\"]",
        r"\[\s*['\"]zul\.[a-zA-Z0-9_.]+['\"]\s*,\s*['\"]([a-zA-Z0-9_]{4})[0-9a-zA-Z_]+['\"]",
        r"\bid=['\"]([a-zA-Z0-9_]{4})x1['\"]"
    ]:
        pm = re.search(p_pat, text)
        if pm:
            prefix = pm.group(1)
            break

    return dtid, prefix

def find_zk_widgets(raw_text):
    """
    Безопасно извлекает все виджеты ZK ['zul.Class','uuid',{props},[children]]
    с учетом любой вложенности фигурных скобок внутри {props}.
    """
    text = normalize_zk_text(raw_text)
    widgets = []
    header_rx = re.compile(r"\[\s*['\"]([a-zA-Z0-9_.$]+)['\"]\s*,\s*['\"]([a-zA-Z0-9_]+)['\"]\s*,\s*\{")
    for m in header_rx.finditer(text):
        w_type = m.group(1)
        w_uuid = m.group(2)
        brace_start = m.end() - 1
        depth = 0
        in_str = None
        escape = False
        end_idx = brace_start
        for i in range(brace_start, min(len(text), brace_start + 15000)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == '\\':
                escape = True
                continue
            if in_str:
                if ch == in_str:
                    in_str = None
                continue
            if ch in ("'", '"'):
                in_str = ch
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end_idx = i
                    break
        props_raw = text[brace_start + 1:end_idx]
        widgets.append({
            'type': w_type,
            'uuid': w_uuid,
            'props_raw': props_raw,
            'pos': m.start()
        })
    return widgets

def meridian_login_session(email_or_login, password, debug_log=None):
    """
    Авторизуется на https://faps.uzairways.com/web.meridian/login.zul
    Пробует логин без домена (имя.фамилия, Имя.Фамилия) и полный email.
    """
    if debug_log is None:
        debug_log = []

    base_login = email_or_login.split('@')[0].strip() if '@' in email_or_login else email_or_login.strip()
    title_login = ".".join([p.capitalize() for p in base_login.split('.')])
    candidates = []
    for c in [base_login, title_login, base_login.lower(), email_or_login.strip()]:
        if c and c not in candidates:
            candidates.append(c)

    last_err = "Не удалось подключиться к Web Meridian"
    for login_candidate in candidates:
        sess = requests.Session()
        sess.verify = False
        sess.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
        })
        try:
            r = sess.get(f"{MERIDIAN_BASE_URL}/login.zul", timeout=18)
            debug_log.append(f"GET login.zul: status={r.status_code}, len={len(r.text)}")
            if not r.ok:
                last_err = f"HTTP {r.status_code} при открытии login.zul"
                continue

            dtid, pfx = extract_zk_dtid_and_prefix(r.text)
            widgets = find_zk_widgets(r.text)
            debug_log.append(f"login.zul parsed: dtid={dtid}, pfx={pfx}, widgets={len(widgets)}")
            if not dtid:
                snippet = re.sub(r'\s+', ' ', r.text[:220])
                last_err = f"Не найден dtid на login.zul (ответ: {snippet})"
                continue

            login_uuid = f"{pfx}g" if pfx else None
            pass_uuid = f"{pfx}j" if pfx else None
            enter_uuid = f"{pfx}s" if pfx else None

            textboxes = [w for w in widgets if 'Textbox' in w['type'] and 'Combobox' not in w['type']]
            pass_box = next((w for w in textboxes if "'password'" in w['props_raw'] or '"password"' in w['props_raw']), None)
            if pass_box:
                pass_uuid = pass_box['uuid']
                prior_boxes = [w for w in textboxes if w['pos'] < pass_box['pos'] and 'readonly:true' not in w['props_raw']]
                if prior_boxes:
                    login_uuid = prior_boxes[-1]['uuid']

            buttons = [w for w in widgets if 'Button' in w['type']]
            enter_btn = next((w for w in buttons if 'Войти' in w['props_raw'] or 'Enter' in w['props_raw'] or 'Login' in w['props_raw']), None)
            if enter_btn:
                enter_uuid = enter_btn['uuid']

            if not login_uuid or not pass_uuid or not enter_uuid:
                last_err = f"Не найдены поля входа (login={login_uuid}, pass={pass_uuid}, btn={enter_uuid})"
                continue

            # Отправляем ТОЛЬКО один клик (без дублирующего onOK)
            au_payload = {
                'dtid': dtid,
                'cmd_0': 'onChange',
                'uuid_0': login_uuid,
                'data_0': json.dumps({"value": login_candidate, "start": 0}),
                'cmd_1': 'onChange',
                'uuid_1': pass_uuid,
                'data_1': json.dumps({"value": password, "start": 0}),
                'cmd_2': 'onClick',
                'uuid_2': enter_uuid,
                'data_2': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
            }

            au_headers = {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'ZK-SID': '1',
                'Origin': 'https://faps.uzairways.com',
                'Referer': r.url
            }
            r_au = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=18)
            au_norm = normalize_zk_text(r_au.text) if r_au.ok else ""
            debug_log.append(f"POST zkau login ({login_candidate}): status={r_au.status_code}, resp={au_norm[:160]}")

            r_wp = sess.get(f"{MERIDIAN_BASE_URL}/workplan.zul", timeout=18)
            wp_norm = normalize_zk_text(r_wp.text)
            debug_log.append(f"GET workplan.zul: url={r_wp.url}, len={len(wp_norm)}")

            if r_wp.ok and ('login.zul' not in r_wp.url) and (
                'workplan-table' in wp_norm or 'План работ' in wp_norm or 'Вылет (UTC)' in wp_norm or 'Персональный налет' in wp_norm
            ):
                return sess, wp_norm
            else:
                last_err = f"Сервер не пустил в План работ (url={r_wp.url}, ответ={au_norm[:120]})"
        except Exception as e:
            last_err = str(e)
            debug_log.append(f"Exception ({login_candidate}): {last_err}")

    raise RuntimeError(last_err)


def fetch_meridian_workplan_reports(sess, wp_initial_text, date_from_str=None, date_to_str=None, latest_only=False, debug_log=None):
    """
    В workplan.zul находит Datebox начала периода и кнопку "Обновить",
    сдвигает дату на -29 дней назад, собирает все иконки отчетов "Полетное задание"
    и открывает dynamic-REP_FT_HY_v9.html.
    """
    if debug_log is None:
        debug_log = []

    dtid, pfx = extract_zk_dtid_and_prefix(wp_initial_text)
    init_widgets = find_zk_widgets(wp_initial_text)
    debug_log.append(f"workplan init: dtid={dtid}, pfx={pfx}, widgets={len(init_widgets)}")
    if not dtid:
        return [], []

    au_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://faps.uzairways.com',
        'Referer': f"{MERIDIAN_BASE_URL}/workplan.zul"
    }

    # Динамически ищем первый Datebox (Период с) и кнопку "Обновить"
    dateboxes = [w for w in init_widgets if 'Datebox' in w['type']]
    datebox_from_uuid = dateboxes[0]['uuid'] if dateboxes else (f"{pfx}52" if pfx else None)

    buttons = [w for w in init_widgets if 'Button' in w['type']]
    refresh_btn = next((w for w in buttons if 'Обновить' in w['props_raw'] or 'refresh.png' in w['props_raw']), None)
    refresh_btn_uuid = refresh_btn['uuid'] if refresh_btn else (f"{pfx}92" if pfx else None)

    combined_wp_text = wp_initial_text

    if datebox_from_uuid and refresh_btn_uuid:
        target_start_dt = datetime.now() - timedelta(days=29)
        if date_from_str:
            try:
                req_dt = datetime.strptime(date_from_str, '%Y-%m-%d')
                if req_dt > target_start_dt:
                    target_start_dt = req_dt
            except Exception:
                pass

        # Пробуем обновить период в разных форматах ZK Datebox (ZK 10 JSON Date и строковый dd.MM.yyyy)
        for idx_fmt, date_payload in enumerate([
            {"value": target_start_dt.strftime("%d.%m.%Y"), "start": 0},
            {"$d": target_start_dt.strftime("%Y.%m.%d.00.00.00.000")},
            {"value": {"$d": target_start_dt.strftime("%Y.%m.%d.00.00.00.000")}}
        ]):
            try:
                refresh_payload = {
                    'dtid': dtid,
                    'cmd_0': 'onChange',
                    'uuid_0': datebox_from_uuid,
                    'data_0': json.dumps(date_payload),
                    'cmd_1': 'onClick',
                    'uuid_1': refresh_btn_uuid,
                    'data_1': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
                }
                r_ref = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=refresh_payload, headers=au_headers, timeout=18)
                if r_ref.ok:
                    ref_norm = normalize_zk_text(r_ref.text)
                    debug_log.append(f"workplan refresh fmt#{idx_fmt}: len={len(ref_norm)}")
                    if 'workplan-leg' in ref_norm or 'Полетное задание' in ref_norm or 'flightTask' in ref_norm:
                        combined_wp_text += "\n" + ref_norm
                        break
            except Exception as e:
                debug_log.append(f"workplan refresh err: {e}")

    widgets = find_zk_widgets(combined_wp_text)

    # Находим все иконки "Полетное задание" (zul.wgt.Image)
    report_targets = []
    seen_uuids = set()
    current_listitem_uuid = None

    for w in widgets:
        if 'Listitem' in w['type']:
            current_listitem_uuid = w['uuid']
        elif 'Image' in w['type'] and ('Полетное задание' in w['props_raw'] or 'flightTask' in w['props_raw']):
            if w['uuid'] not in seen_uuids:
                seen_uuids.add(w['uuid'])
                report_targets.append({
                    'img_uuid': w['uuid'],
                    'row_uuid': current_listitem_uuid
                })

    debug_log.append(f"workplan report icons found: {len(report_targets)}")

    # Извлекаем даты перелетов пассажиром ([пас] / Пассажир по заданию)
    deadhead_dates = []
    current_date_str = None
    for w in widgets:
        if 'Label' in w['type']:
            val_m = re.search(r"value\s*:\s*['\"]([^'\"]+)['\"]", w['props_raw'])
            if val_m:
                v = val_m.group(1)
                dm = re.match(r"^(\d{2}\.\d{2}\.\d{4})\s*\(", v)
                if dm:
                    current_date_str = dm.group(1)
                elif ('[пас]' in v or 'Пассажир по заданию' in v) and current_date_str:
                    if current_date_str not in deadhead_dates:
                        deadhead_dates.append(current_date_str)

    if latest_only and report_targets:
        report_targets = [report_targets[-1]]

    html_reports = []
    listboxes = [w for w in init_widgets if 'Listbox' in w['type'] and 'workplan-table' in w['props_raw']]
    listbox_uuid = listboxes[0]['uuid'] if listboxes else (f"{pfx}g2" if pfx else None)

    ft_btn = next((w for w in buttons if 'Полетное задание' in w['props_raw'] or 'FT' in w['props_raw']), None)
    ft_btn_uuid = ft_btn['uuid'] if ft_btn else (f"{pfx}u2" if pfx else None)

    for target in report_targets:
        try:
            # Сначала кликаем по самой иконке Полетного задания в строке рейса
            r_click = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data={
                'dtid': dtid,
                'cmd_0': 'onClick',
                'uuid_0': target['img_uuid'],
                'data_0': json.dumps({"pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10})
            }, headers=au_headers, timeout=18)
            click_norm = normalize_zk_text(r_click.text) if r_click.ok else ""

            # Если прямое нажатие на иконку не вернуло ссылку, выделяем строку и нажимаем нижнюю кнопку "Полетное задание"
            if 'dynamic-html' not in click_norm and listbox_uuid and target['row_uuid'] and ft_btn_uuid:
                r_btn = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data={
                    'dtid': dtid,
                    'cmd_0': 'onSelect',
                    'uuid_0': listbox_uuid,
                    'data_0': json.dumps({
                        "items": [target['row_uuid']],
                        "reference": target['row_uuid'],
                        "clearFirst": True,
                        "selectAll": False,
                        "pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10
                    }),
                    'cmd_1': 'onClick',
                    'uuid_1': ft_btn_uuid,
                    'data_1': json.dumps({"pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10})
                }, headers=au_headers, timeout=18)
                if r_btn.ok:
                    click_norm += "\n" + normalize_zk_text(r_btn.text)

            iframe_m = re.search(r"((?:/web\.meridian/)?reports/dynamic-html/[^'\"\s<>]+\.html[^'\"\s<>]*)", click_norm)
            if not iframe_m:
                continue

            rel_path = iframe_m.group(1)
            if not rel_path.startswith('/'):
                rel_path = '/web.meridian/' + rel_path
            report_url = "https://faps.uzairways.com" + rel_path

            r_rep = sess.get(report_url, timeout=18)
            if r_rep.ok and ('flightCrew' in r_rep.text or 'Flight Task Report' in r_rep.text):
                if date_from_str and date_to_str:
                    fd_m = re.search(r'data-key="flightDate"[^>]*>(\d{2})\.(\d{2})\.(\d{4})<', r_rep.text)
                    if fd_m:
                        rep_ymd = f"{fd_m.group(3)}-{fd_m.group(2)}-{fd_m.group(1)}"
                        if not (date_from_str <= rep_ymd <= date_to_str):
                            continue
                if r_rep.text not in html_reports:
                    html_reports.append(r_rep.text)
        except Exception as e:
            debug_log.append(f"report click err: {e}")
            continue

    debug_log.append(f"workplan html_reports fetched: {len(html_reports)}")
    return html_reports, deadhead_dates


def parse_zk_pft_rows(raw_zk_text):
    """
    Извлекает строки правой таблицы рейсов из ответа personalFlightTime.zul.
    Разбирает каждую строку Listitem по ее ячейкам Listcell, чтобы пустой № п/з никогда не сдвигал столбцы.
    """
    text = normalize_zk_text(raw_zk_text)
    rows = []
    date_rx = re.compile(r"^\d{2}\s+[а-яёА-ЯЁ]{3}[а-яёА-ЯЁ\.]*\s+\d{4}$")

    item_chunks = re.split(r"\[\s*['\"]zul\.sel\.Listitem['\"]\s*,", text)
    for chunk in item_chunks[1:]:
        cell_chunks = re.split(r"\[\s*['\"]zul\.sel\.Listcell['\"]\s*,", chunk)
        if len(cell_chunks) >= 9:
            cells = []
            for c_chunk in cell_chunks[1:10]:
                lbl_m = re.search(r"\[\s*['\"]zul\.wgt\.Label['\"][\s\S]{1,140}?\bvalue\s*:\s*['\"]([^'\"]*)['\"]", c_chunk)
                cells.append(lbl_m.group(1).strip() if lbl_m else "")
            if cells and date_rx.match(cells[0]):
                rows.append(cells)

    if not rows:
        labels = [m.group(1).strip() for m in re.finditer(r"\bvalue\s*:\s*['\"]([^'\"]*)['\"]", text)]
        i = 0
        while i <= len(labels) - 8:
            if date_rx.match(labels[i]):
                row = labels[i:i+9] if (i + 9 <= len(labels)) else (labels[i:i+8] + ["0.0"])
                rows.append(row)
                i += 9
            else:
                i += 1

    return rows


def fetch_meridian_personal_flight_time(sess, date_from_str, date_to_str, debug_log=None):
    """
    Заходит в personalFlightTime.zul, выбирает нужные месяцы из левой таблицы (<PFX>d2)
    и мгновенно возвращает все строки рейсов из правой таблицы (<PFX>m2).
    """
    if debug_log is None:
        debug_log = []

    r_pft = sess.get(f"{MERIDIAN_BASE_URL}/personalFlightTime.zul", timeout=18)
    if not r_pft.ok:
        debug_log.append(f"GET personalFlightTime.zul failed: {r_pft.status_code}")
        return []

    pft_norm = normalize_zk_text(r_pft.text)
    dtid, pfx = extract_zk_dtid_and_prefix(pft_norm)
    widgets = find_zk_widgets(pft_norm)
    debug_log.append(f"pft init: dtid={dtid}, pfx={pfx}, widgets={len(widgets)}")
    if not dtid:
        return []

    d_from = datetime.strptime(date_from_str[:7] + "-01", "%Y-%m-%d")
    d_to = datetime.strptime(date_to_str[:7] + "-01", "%Y-%m-%d")
    target_month_labels = set()
    cur = d_from
    while cur <= d_to:
        m_name = RU_MONTH_NAMES.get(cur.month, '')
        target_month_labels.add(f"{m_name} {cur.year}")
        if cur.month == 12:
            cur = datetime(cur.year + 1, 1, 1)
        else:
            cur = datetime(cur.year, cur.month + 1, 1)

    listboxes = [w for w in widgets if 'Listbox' in w['type']]
    months_listbox_uuid = listboxes[0]['uuid'] if listboxes else (f"{pfx}d2" if pfx else None)

    month_item_uuids = []
    seen_m_uuids = set()
    last_listitem_uuid = None
    for w in widgets:
        if 'Listitem' in w['type']:
            last_listitem_uuid = w['uuid']
        elif 'Label' in w['type'] and last_listitem_uuid:
            val_m = re.search(r"value\s*:\s*['\"]([^'\"]+)['\"]", w['props_raw'])
            if val_m:
                lbl_val = val_m.group(1).strip().lower()
                if lbl_val in target_month_labels and last_listitem_uuid not in seen_m_uuids:
                    seen_m_uuids.add(last_listitem_uuid)
                    month_item_uuids.append((lbl_val, last_listitem_uuid))
                    last_listitem_uuid = None

    debug_log.append(f"pft target months={list(target_month_labels)}, matched_uuids={month_item_uuids}")

    all_rows = []
    initial_rows = parse_zk_pft_rows(pft_norm)
    for r in initial_rows:
        if r not in all_rows:
            all_rows.append(r)

    au_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://faps.uzairways.com',
        'Referer': f"{MERIDIAN_BASE_URL}/personalFlightTime.zul"
    }

    if months_listbox_uuid:
        for m_lbl, item_uuid in month_item_uuids:
            try:
                au_payload = {
                    'dtid': dtid,
                    'cmd_0': 'onSelect',
                    'uuid_0': months_listbox_uuid,
                    'data_0': json.dumps({
                        "items": [item_uuid],
                        "reference": item_uuid,
                        "clearFirst": True,
                        "selectAll": False,
                        "pageX": 15,
                        "pageY": 15,
                        "which": 1,
                        "x": 15,
                        "y": 15
                    }),
                    'cmd_1': 'onClick',
                    'uuid_1': item_uuid,
                    'data_1': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
                }
                r_sel = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=18)
                if r_sel.ok:
                    m_rows = parse_zk_pft_rows(r_sel.text)
                    debug_log.append(f"pft month '{m_lbl}' ({item_uuid}): parsed {len(m_rows)} rows")
                    for row in m_rows:
                        if row not in all_rows:
                            all_rows.append(row)
            except Exception as e:
                debug_log.append(f"pft month err ({m_lbl}): {e}")
                continue

    debug_log.append(f"pft total rows: {len(all_rows)}")
    return all_rows


@app.route('/', methods=['GET'])
def home():
    return "Гибридный мост Flight Log v3.1.3 (Web Meridian + Почта Exchange + Расчетные листки) работает штатно!"


@app.route('/fetch-latest-report', methods=['POST'])
def fetch_latest_report():
    data = request.json or {}
    email_addr = (data.get('email') or '').strip()
    password = data.get('password') or ''
    server = data.get('server', 'mail.uzairways.com')
    subject_filter = (data.get('subject') or 'Полетное задание').lower().replace('ё', 'е')
    action = (data.get('action') or '').strip()
    date_from_str = (data.get('dateFrom') or '').strip()
    date_to_str = (data.get('dateTo') or '').strip()

    if not email_addr or not password:
        return jsonify({"error": "Не указан логин или пароль."}), 400

    # ==========================================================================
    # РЕЖИМ 1: ЗАГРУЗКА С САЙТА WEB MERIDIAN (КРАЙНИЙ РЕЙС ИЛИ ЗА ПЕРИОД)
    # ==========================================================================
    if action in ('meridian_latest', 'meridian_range'):
        debug_log = []
        try:
            sess, wp_text = meridian_login_session(email_addr, password, debug_log=debug_log)

            if action == 'meridian_latest':
                html_reports, deadhead_dates = fetch_meridian_workplan_reports(
                    sess, wp_text, latest_only=True, debug_log=debug_log
                )
                if html_reports:
                    return jsonify({
                        "mode": "meridian_latest",
                        "htmlReports": html_reports,
                        "deadheadDates": deadhead_dates,
                        "debugLog": debug_log
                    })
            elif action == 'meridian_range' and date_from_str and date_to_str:
                today_dt = datetime.now()
                cutoff_30d = (today_dt - timedelta(days=30)).strftime('%Y-%m-%d')

                html_reports = []
                deadhead_dates = []
                pft_rows = []

                # 1. Мгновенно забираем строки из Персонального налета за все выбранные месяцы
                pft_rows = fetch_meridian_personal_flight_time(
                    sess, date_from_str, date_to_str, debug_log=debug_log
                )

                # 2. Если диапазон затрагивает последние 30 дней (+60 дней вперед) — забираем полные карточки из Плана работ
                if date_to_str >= cutoff_30d:
                    html_reports, deadhead_dates = fetch_meridian_workplan_reports(
                        sess, wp_text, date_from_str=date_from_str, date_to_str=date_to_str,
                        latest_only=False, debug_log=debug_log
                    )

                return jsonify({
                    "mode": "meridian_range",
                    "htmlReports": html_reports,
                    "deadheadDates": deadhead_dates,
                    "pftRows": pft_rows,
                    "debugLog": debug_log,
                    "needsBackgroundMailSync": bool(date_from_str < cutoff_30d)
                })
        except Exception as mer_err:
            if action == 'meridian_range':
                return jsonify({
                    "mode": "meridian_range",
                    "meridianError": str(mer_err),
                    "debugLog": debug_log,
                    "htmlReports": [],
                    "deadheadDates": [],
                    "pftRows": [],
                    "needsBackgroundMailSync": True
                })

    # ==========================================================================
    # РЕЖИМ 2: ПОЧТА EXCHANGE (ФОЛБЭК, ФОНОВАЯ ДОГРУЗКА ДЕТАЛЕЙ И РАСЧЕТНЫЕ ЛИСТКИ)
    # ==========================================================================
    try:
        creds = Credentials(username=email_addr, password=password)
        config = Configuration(server=server, credentials=creds)
        account = Account(
            primary_smtp_address=email_addr,
            config=config,
            autodiscover=False,
            access_type=DELEGATE
        )

        try:
            base_qs = account.inbox.filter(has_attachments=True)
        except Exception:
            base_qs = account.inbox.all()

        payslip_date_to_str = date_to_str
        req_month_from = date_from_str[:7] if len(date_from_str) >= 7 else ""
        req_month_to = date_to_str[:7] if len(date_to_str) >= 7 else ""

        if date_to_str:
            try:
                dt_to_obj = datetime.strptime(date_to_str, '%Y-%m-%d') + timedelta(days=45)
                payslip_date_to_str = dt_to_obj.strftime('%Y-%m-%d')
            except Exception:
                payslip_date_to_str = date_to_str

        if action == 'list' and date_from_str and date_to_str:
            qs = base_qs.only(
                'subject', 'datetime_received', 'message_id', 'sender'
            ).order_by('-datetime_received')

            items_list = []
            for item in qs[:2000]:
                dt_rec = getattr(item, 'datetime_received', None)
                if not dt_rec:
                    continue

                local_dt = dt_rec + timedelta(hours=5)
                item_date_str = local_dt.strftime('%Y-%m-%d')

                if item_date_str < date_from_str:
                    break

                if not is_trusted_sender(item):
                    continue

                raw_subj = getattr(item, 'subject', '') or ''

                if is_payslip_email(item) and date_from_str <= item_date_str <= payslip_date_to_str:
                    p_key, p_ym = extract_payslip_month_info(raw_subj)
                    if item_date_str > date_to_str and p_ym and req_month_from and req_month_to:
                        if not (req_month_from <= p_ym <= req_month_to):
                            continue
                    items_list.append({
                        "docType": "payslip",
                        "payslipMonthKey": p_key or "",
                        "subject": raw_subj,
                        "itemId": getattr(item, 'id', '') or '',
                        "changekey": getattr(item, 'changekey', '') or '',
                        "messageId": getattr(item, 'message_id', None) or str(dt_rec),
                        "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                        "emailTimestamp": int(dt_rec.timestamp() * 1000)
                    })
                    continue

                if date_from_str <= item_date_str <= date_to_str:
                    if is_flight_report_email(item, subject_filter):
                        items_list.append({
                            "docType": "flight_report",
                            "subject": raw_subj,
                            "itemId": getattr(item, 'id', '') or '',
                            "changekey": getattr(item, 'changekey', '') or '',
                            "messageId": getattr(item, 'message_id', None) or str(dt_rec),
                            "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                            "emailTimestamp": int(dt_rec.timestamp() * 1000)
                        })

            items_list.reverse()
            return jsonify({
                "mode": "list",
                "count": len(items_list),
                "items": items_list
            })

        if action == 'fetch_one':
            item_id = (data.get('itemId') or '').strip()
            msg_id = (data.get('messageId') or '').strip()

            target_item = None
            if item_id:
                try:
                    target_item = account.inbox.get(id=item_id)
                except Exception:
                    target_item = None

            if target_item is None and msg_id:
                matches = list(account.inbox.filter(message_id=msg_id).only(
                    'subject', 'datetime_received', 'message_id', 'sender', 'attachments'
                )[:1])
                if matches:
                    target_item = matches[0]

            if target_item is None or not is_trusted_sender(target_item):
                return jsonify({"skip": True, "reason": "untrusted_or_not_found"})

            dt_rec = getattr(target_item, 'datetime_received', None)
            local_dt = (dt_rec + timedelta(hours=5)) if dt_rec else datetime.now()
            email_ts = int(dt_rec.timestamp() * 1000) if dt_rec else int(datetime.now().timestamp() * 1000)
            raw_subj = getattr(target_item, 'subject', '') or ''
            is_payslip = is_payslip_email(target_item)

            for attachment in (getattr(target_item, 'attachments', None) or []):
                if is_valid_pdf_attachment(attachment):
                    att_name = attachment.name or 'Document.pdf'
                    if 'рлист' in att_name.lower():
                        is_payslip = True
                    doc_type = "payslip" if is_payslip else "flight_report"
                    p_key, _ = extract_payslip_month_info(raw_subj + " " + att_name) if is_payslip else (None, None)

                    pdf_b64 = base64.b64encode(attachment.content).decode('utf-8')
                    return jsonify({
                        "mode": "single",
                        "docType": doc_type,
                        "payslipMonthKey": p_key or "",
                        "subject": raw_subj,
                        "fileName": att_name,
                        "messageId": getattr(target_item, 'message_id', None) or str(dt_rec),
                        "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                        "emailTimestamp": email_ts,
                        "pdfBase64": pdf_b64
                    })

            return jsonify({"skip": True, "reason": "no_valid_pdf"})

        qs_latest = base_qs.only(
            'subject', 'datetime_received', 'message_id', 'sender'
        ).order_by('-datetime_received')

        latest_flight_payload = None
        latest_payslip_payload = None

        for item in qs_latest[:60]:
            if not is_trusted_sender(item):
                continue

            raw_subj = getattr(item, 'subject', '') or ''

            if latest_payslip_payload is None and is_payslip_email(item):
                full_ps = account.inbox.get(id=item.id)
                for attachment in (getattr(full_ps, 'attachments', None) or []):
                    if is_valid_pdf_attachment(attachment):
                        att_name = attachment.name or 'Payslip.pdf'
                        dt_rec = getattr(full_ps, 'datetime_received', None)
                        local_dt = (dt_rec + timedelta(hours=5)) if dt_rec else datetime.now()
                        email_ts = int(dt_rec.timestamp() * 1000) if dt_rec else int(datetime.now().timestamp() * 1000)
                        p_key, _ = extract_payslip_month_info(raw_subj + " " + att_name)
                        latest_payslip_payload = {
                            "docType": "payslip",
                            "payslipMonthKey": p_key or "",
                            "subject": raw_subj,
                            "fileName": att_name,
                            "messageId": getattr(full_ps, 'message_id', None) or str(dt_rec),
                            "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                            "emailTimestamp": email_ts,
                            "pdfBase64": base64.b64encode(attachment.content).decode('utf-8')
                        }
                        break

            if latest_flight_payload is None and is_flight_report_email(item, subject_filter):
                full_fr = account.inbox.get(id=item.id)
                for attachment in (getattr(full_fr, 'attachments', None) or []):
                    if is_valid_pdf_attachment(attachment):
                        att_name = attachment.name or 'Report.pdf'
                        dt_rec = getattr(full_fr, 'datetime_received', None)
                        local_dt = (dt_rec + timedelta(hours=5)) if dt_rec else datetime.now()
                        email_ts = int(dt_rec.timestamp() * 1000) if dt_rec else int(datetime.now().timestamp() * 1000)
                        latest_flight_payload = {
                            "mode": "latest",
                            "docType": "flight_report",
                            "subject": raw_subj,
                            "fileName": att_name,
                            "messageId": getattr(full_fr, 'message_id', None) or str(dt_rec),
                            "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                            "emailTimestamp": email_ts,
                            "pdfBase64": base64.b64encode(attachment.content).decode('utf-8')
                        }
                        break

            if latest_flight_payload is not None and latest_payslip_payload is not None:
                break

        if latest_flight_payload:
            if latest_payslip_payload:
                latest_flight_payload["latestPayslip"] = latest_payslip_payload
            return jsonify(latest_flight_payload)

        if latest_payslip_payload:
            latest_payslip_payload["mode"] = "latest"
            return jsonify(latest_payslip_payload)

        return jsonify({"error": "Новых отчетов ни в Web Meridian, ни на почте не найдено."}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
