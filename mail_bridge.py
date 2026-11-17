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
    m = re.search(r"\bdt\s*:\s*['\"]([^'\"]+)['\"]", text)
    if m:
        dtid = m.group(1)
    else:
        m2 = re.search(r"/zkau/view/([^/\"']+)/", text)
        if m2:
            dtid = m2.group(1)

    prefix = None
    pm = re.search(r"zkmx\(\s*\[\s*0\s*,\s*['\"]([a-zA-Z0-9_]{4})[a-zA-Z0-9_]*['\"]", text)
    if not pm:
        pm = re.search(r"\[\s*['\"]zul\.[a-zA-Z0-9_.]+['\"]\s*,\s*['\"]([a-zA-Z0-9_]{4})[0-9a-zA-Z_]+['\"]", text)
    if pm:
        prefix = pm.group(1)

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

def meridian_login_session(email_or_login, password):
    """
    Авторизуется на https://faps.uzairways.com/web.meridian/login.zul
    Пробует логин без домена (имя.фамилия, Имя.Фамилия) и полный email.
    """
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
            'User-Agent': 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
        })
        try:
            r = sess.get(f"{MERIDIAN_BASE_URL}/login.zul", timeout=20)
            if not r.ok:
                last_err = f"HTTP {r.status_code} при открытии login.zul"
                continue

            dtid, pfx = extract_zk_dtid_and_prefix(r.text)
            widgets = find_zk_widgets(r.text)
            if not dtid:
                last_err = "Не удалось получить dtid страницы входа Web Meridian"
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
                last_err = "Не найдены поля логина/пароля на странице Web Meridian"
                continue

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
                'data_2': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15}),
                'cmd_3': 'onOK',
                'uuid_3': pass_uuid,
                'data_3': json.dumps({"reference": pass_uuid, "which": 13})
            }

            au_headers = {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'ZK-SID': '1',
                'Origin': 'https://faps.uzairways.com',
                'Referer': f"{MERIDIAN_BASE_URL}/login.zul"
            }
            sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=20)

            r_wp = sess.get(f"{MERIDIAN_BASE_URL}/workplan.zul", timeout=20)
            wp_norm = normalize_zk_text(r_wp.text)
            if r_wp.ok and ('workplan-table' in wp_norm or 'План работ' in wp_norm or 'Вылет (UTC)' in wp_norm or 'Персональный налет' in wp_norm):
                return sess, wp_norm
            else:
                last_err = "Неверный логин или пароль Web Meridian"
        except Exception as e:
            last_err = str(e)

    raise RuntimeError(last_err)


def fetch_meridian_workplan_reports(sess, wp_initial_text, date_from_str=None, date_to_str=None, latest_only=False):
    """
    В workplan.zul сдвигает дату начала периода на -30 дней (кнопка Обновить <PFX>92),
    собирает все иконки отчетов "Полетное задание", открывает dynamic-REP_FT_HY_v9.html
    и возвращает список полных HTML-отчетов и дат перелетов пассажиром ([пас]).
    """
    dtid, pfx = extract_zk_dtid_and_prefix(wp_initial_text)
    if not dtid:
        return [], []

    au_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://faps.uzairways.com',
        'Referer': f"{MERIDIAN_BASE_URL}/workplan.zul"
    }

    combined_wp_text = wp_initial_text

    if pfx:
        datebox_from_uuid = f"{pfx}52"
        refresh_btn_uuid = f"{pfx}92"
        target_start_dt = datetime.now() - timedelta(days=29)
        if date_from_str:
            try:
                req_dt = datetime.strptime(date_from_str, '%Y-%m-%d')
                if req_dt > target_start_dt:
                    target_start_dt = req_dt
            except Exception:
                pass

        for date_val in [
            {"$d": target_start_dt.strftime("%Y.%m.%d.00.00.00.000")},
            target_start_dt.strftime("%d.%m.%Y")
        ]:
            try:
                refresh_payload = {
                    'dtid': dtid,
                    'cmd_0': 'onChange',
                    'uuid_0': datebox_from_uuid,
                    'data_0': json.dumps({"value": date_val}),
                    'cmd_1': 'onClick',
                    'uuid_1': refresh_btn_uuid,
                    'data_1': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
                }
                r_ref = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=refresh_payload, headers=au_headers, timeout=20)
                if r_ref.ok:
                    ref_norm = normalize_zk_text(r_ref.text)
                    if 'Полетное задание' in ref_norm or 'flightTask' in ref_norm or 'workplan-leg' in ref_norm:
                        combined_wp_text = wp_initial_text + "\n" + ref_norm
                        break
            except Exception:
                continue

    widgets = find_zk_widgets(combined_wp_text)

    report_targets = []
    seen_uuids = set()
    current_listitem_uuid = None
    last_macro_uuid = None

    for w in widgets:
        if 'Listitem' in w['type']:
            current_listitem_uuid = w['uuid']
        elif 'HtmlMacroComponent' in w['type'] or 'Macro' in w['type']:
            last_macro_uuid = w['uuid']
        elif 'Image' in w['type'] and ('Полетное задание' in w['props_raw'] or 'flightTask' in w['props_raw']):
            if w['uuid'] not in seen_uuids:
                seen_uuids.add(w['uuid'])
                report_targets.append({
                    'img_uuid': w['uuid'],
                    'macro_uuid': last_macro_uuid,
                    'row_uuid': current_listitem_uuid
                })

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
    listbox_uuid = f"{pfx}g2" if pfx else None
    ft_btn_uuid = f"{pfx}u2" if pfx else None

    for target in report_targets:
        try:
            au_payload = {'dtid': dtid}
            cmd_idx = 0

            if listbox_uuid and target['row_uuid']:
                au_payload[f'cmd_{cmd_idx}'] = 'onSelect'
                au_payload[f'uuid_{cmd_idx}'] = listbox_uuid
                au_payload[f'data_{cmd_idx}'] = json.dumps({
                    "items": [target['row_uuid']],
                    "reference": target['row_uuid'],
                    "clearFirst": True,
                    "selectAll": False,
                    "pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10
                })
                cmd_idx += 1

            au_payload[f'cmd_{cmd_idx}'] = 'onClick'
            au_payload[f'uuid_{cmd_idx}'] = target['img_uuid']
            au_payload[f'data_{cmd_idx}'] = json.dumps({"pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10})
            cmd_idx += 1

            if target['macro_uuid']:
                au_payload[f'cmd_{cmd_idx}'] = 'onClick'
                au_payload[f'uuid_{cmd_idx}'] = target['macro_uuid']
                au_payload[f'data_{cmd_idx}'] = json.dumps({"pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10})
                cmd_idx += 1

            r_click = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=20)
            click_norm = normalize_zk_text(r_click.text) if r_click.ok else ""

            if 'reports/dynamic-html/' not in click_norm and ft_btn_uuid:
                r_btn = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data={
                    'dtid': dtid,
                    'cmd_0': 'onClick',
                    'uuid_0': ft_btn_uuid,
                    'data_0': json.dumps({"pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10})
                }, headers=au_headers, timeout=20)
                if r_btn.ok:
                    click_norm += "\n" + normalize_zk_text(r_btn.text)

            iframe_m = re.search(r"(/web\.meridian/reports/dynamic-html/[^'\"\s<>]+\.html)", click_norm)
            if not iframe_m:
                iframe_m = re.search(r"(reports/dynamic-html/[^'\"\s<>]+\.html)", click_norm)
            if not iframe_m:
                continue

            rel_path = iframe_m.group(1)
            if not rel_path.startswith('/'):
                rel_path = '/web.meridian/' + rel_path
            report_url = "https://faps.uzairways.com" + rel_path

            r_rep = sess.get(report_url, timeout=20)
            if r_rep.ok and ('flightCrew' in r_rep.text or 'Flight Task Report' in r_rep.text):
                if date_from_str and date_to_str:
                    fd_m = re.search(r'data-key="flightDate"[^>]*>(\d{2})\.(\d{2})\.(\d{4})<', r_rep.text)
                    if fd_m:
                        rep_ymd = f"{fd_m.group(3)}-{fd_m.group(2)}-{fd_m.group(1)}"
                        if not (date_from_str <= rep_ymd <= date_to_str):
                            continue
                if r_rep.text not in html_reports:
                    html_reports.append(r_rep.text)
        except Exception:
            continue

    return html_reports, deadhead_dates


def parse_zk_pft_rows(raw_zk_text):
    """
    Извлекает строки правой таблицы рейсов из ответа personalFlightTime.zul.
    Разбирает каждую строку Listitem по ее ячейкам Listcell, чтобы пустой № п/з никогда не сдвигал столбцы!
    """
    text = normalize_zk_text(raw_zk_text)
    rows = []
    date_rx = re.compile(r"^\d{2}\s+[а-яёА-ЯЁ]{3}[а-яёА-ЯЁ\.]*\s+\d{4}$")

    # Разбиваем текст по блокам Listitem
    item_chunks = re.split(r"\[\s*['\"]zul\.sel\.Listitem['\"]\s*,", text)
    for chunk in item_chunks[1:]:
        cell_chunks = re.split(r"\[\s*['\"]zul\.sel\.Listcell['\"]\s*,", chunk)
        if len(cell_chunks) >= 9:
            cells = []
            for c_chunk in cell_chunks[1:10]:
                lbl_m = re.search(r"\[\s*['\"]zul\.wgt\.Label['\"][\s\S]{1,120}?\bvalue\s*:\s*['\"]([^'\"]*)['\"]", c_chunk)
                cells.append(lbl_m.group(1).strip() if lbl_m else "")
            if cells and date_rx.match(cells[0]):
                rows.append(cells)

    # Резервный проход по плоскому списку меток, если формат ответа отличается
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


def fetch_meridian_personal_flight_time(sess, date_from_str, date_to_str):
    """
    Заходит в personalFlightTime.zul, выбирает нужные месяцы из левой таблицы (<PFX>d2)
    и мгновенно возвращает все строки рейсов из правой таблицы (<PFX>m2).
    """
    r_pft = sess.get(f"{MERIDIAN_BASE_URL}/personalFlightTime.zul", timeout=20)
    if not r_pft.ok:
        return []

    pft_norm = normalize_zk_text(r_pft.text)
    dtid, pfx = extract_zk_dtid_and_prefix(pft_norm)
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

    months_listbox_uuid = f"{pfx}d2" if pfx else None

    # Прямой поиск пар (item_uuid, 'месяц ГГГГ') по регулярному выражению
    month_item_uuids = []
    seen_m_uuids = set()
    for m in re.finditer(r"\[\s*['\"]zul\.sel\.Listitem['\"]\s*,\s*['\"]([a-zA-Z0-9_]+)['\"][\s\S]{1,350}?\bvalue\s*:\s*['\"]([а-яёА-ЯЁ]+\s+20\d{2})['\"]", pft_norm):
        item_uuid = m.group(1)
        lbl_val = m.group(2).strip().lower()
        if lbl_val in target_month_labels and item_uuid not in seen_m_uuids:
            seen_m_uuids.add(item_uuid)
            month_item_uuids.append((lbl_val, item_uuid))

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
                r_sel = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=20)
                if r_sel.ok:
                    m_rows = parse_zk_pft_rows(r_sel.text)
                    for row in m_rows:
                        if row not in all_rows:
                            all_rows.append(row)
            except Exception:
                continue

    return all_rows


@app.route('/', methods=['GET'])
def home():
    return "Гибридный мост Flight Log v3.1.2 (Web Meridian + Почта Exchange + Расчетные листки) работает штатно!"


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
        try:
            sess, wp_text = meridian_login_session(email_addr, password)

            if action == 'meridian_latest':
                html_reports, deadhead_dates = fetch_meridian_workplan_reports(sess, wp_text, latest_only=True)
                if html_reports:
                    return jsonify({
                        "mode": "meridian_latest",
                        "htmlReports": html_reports,
                        "deadheadDates": deadhead_dates
                    })
            elif action == 'meridian_range' and date_from_str and date_to_str:
                today_dt = datetime.now()
                cutoff_30d = (today_dt - timedelta(days=30)).strftime('%Y-%m-%d')

                html_reports = []
                deadhead_dates = []
                pft_rows = []

                # 1. Мгновенно забираем строки из Персонального налета за все выбранные месяцы
                pft_rows = fetch_meridian_personal_flight_time(sess, date_from_str, date_to_str)

                # 2. Если диапазон затрагивает последние 30 дней (+60 дней вперед) — забираем полные карточки из Плана работ
                if date_to_str >= cutoff_30d:
                    html_reports, deadhead_dates = fetch_meridian_workplan_reports(
                        sess, wp_text, date_from_str=date_from_str, date_to_str=date_to_str, latest_only=False
                    )

                return jsonify({
                    "mode": "meridian_range",
                    "htmlReports": html_reports,
                    "deadheadDates": deadhead_dates,
                    "pftRows": pft_rows,
                    "needsBackgroundMailSync": bool(date_from_str < cutoff_30d)
                })
        except Exception as mer_err:
            if action == 'meridian_range':
                return jsonify({
                    "mode": "meridian_range",
                    "meridianError": str(mer_err),
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

        # БЫСТРЫЙ СПИСОК ПИСЕМ ЗА ПЕРИОД (ДЛЯ ФОНОВОЙ ПРОВЕРКИ ПОЧТЫ)
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

        # СКАЧИВАНИЕ ОДНОГО КОНКРЕТНОГО PDF С ПОЧТЫ
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

        # СТАНДАРТНЫЙ ПОИСК КРАЙНЕГО РЕЙСА И СВЕЖЕГО КВИТКА НА ПОЧТЕ
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
