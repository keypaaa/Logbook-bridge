import os
import re
import json
import base64
from datetime import datetime, timedelta
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from exchangelib import Credentials, Account, Configuration, DELEGATE, FileAttachment

app = Flask(__name__)
CORS(app)

MAX_PDF_SIZE_BYTES = 25 * 1024 * 1024  # Защита от слишком больших файлов (макс. 25 МБ)
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

def extract_zk_dtid(text):
    m = re.search(r"\bdt\s*:\s*['\"]([^'\"]+)['\"]", text)
    if m:
        return m.group(1)
    m2 = re.search(r"/zkau/view/([^/\"']+)/", text)
    if m2:
        return m2.group(1)
    return None

def find_zk_widgets(text):
    """
    Находит все виджеты ZK из инициализационного скрипта zkmx/zkac:
    ['zul.inp.Textbox','uuid',{props},[children]]
    Возвращает список словарей: {'type': ..., 'uuid': ..., 'props': ...}
    """
    widgets = []
    pattern = re.compile(r"\[\s*['\"]([a-zA-Z0-9_.$]+)['\"]\s*,\s*['\"]([a-zA-Z0-9_]+)['\"]\s*,\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}")
    for m in pattern.finditer(text):
        w_type, w_uuid, w_props = m.group(1), m.group(2), m.group(3)
        widgets.append({
            'type': w_type,
            'uuid': w_uuid,
            'props_raw': w_props,
            'pos': m.start()
        })
    return widgets

def meridian_login_session(email_or_login, password):
    """
    Авторизуется на https://faps.uzairways.com/web.meridian/login.zul
    Пробует логин без @uzairways.com и полный email.
    Возвращает авторизованный requests.Session() или вызывает исключение.
    """
    base_login = email_or_login.split('@')[0].strip() if '@' in email_or_login else email_or_login.strip()
    candidates = [base_login]
    if email_or_login.strip() not in candidates:
        candidates.append(email_or_login.strip())

    last_err = "Не удалось подключиться к Web Meridian"
    for login_candidate in candidates:
        sess = requests.Session()
        sess.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
        })
        try:
            r = sess.get(f"{MERIDIAN_BASE_URL}/login.zul", timeout=20)
            if not r.ok:
                last_err = f"HTTP {r.status_code} при открытии login.zul"
                continue

            dtid = extract_zk_dtid(r.text)
            widgets = find_zk_widgets(r.text)
            if not dtid or not widgets:
                last_err = "Не удалось получить dtid страницы входа Web Meridian"
                continue

            textboxes = [w for w in widgets if 'Textbox' in w['type'] and 'Combobox' not in w['type']]
            pass_box = next((w for w in textboxes if "'password'" in w['props_raw'] or '"password"' in w['props_raw']), None)
            login_box = None
            if pass_box:
                prior_boxes = [w for w in textboxes if w['pos'] < pass_box['pos'] and 'readonly:true' not in w['props_raw']]
                if prior_boxes:
                    login_box = prior_boxes[-1]
            if not login_box and len(textboxes) >= 2:
                login_box = textboxes[0]

            buttons = [w for w in widgets if 'Button' in w['type']]
            enter_btn = next((w for w in buttons if 'Войти' in w['props_raw'] or 'Enter' in w['props_raw'] or 'Login' in w['props_raw']), None)
            if not enter_btn and buttons:
                enter_btn = buttons[0]

            if not login_box or not pass_box or not enter_btn:
                last_err = "Не найдены поля ввода логина/пароля на странице Web Meridian"
                continue

            au_payload = {
                'dtid': dtid,
                'cmd_0': 'onChange',
                'uuid_0': login_box['uuid'],
                'data_0': json.dumps({"value": login_candidate, "start": 0}),
                'cmd_1': 'onChange',
                'uuid_1': pass_box['uuid'],
                'data_1': json.dumps({"value": password, "start": 0}),
                'cmd_2': 'onClick',
                'uuid_2': enter_btn['uuid'],
                'data_2': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
            }

            au_headers = {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'ZK-SID': '1',
                'Origin': 'https://faps.uzairways.com',
                'Referer': f"{MERIDIAN_BASE_URL}/login.zul"
            }
            r_au = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=20)

            # Проверяем, пустило ли в workplan.zul
            r_wp = sess.get(f"{MERIDIAN_BASE_URL}/workplan.zul", timeout=20)
            if r_wp.ok and ('login.zul' not in r_wp.url) and ('workplan-table' in r_wp.text or 'План работ' in r_wp.text or 'Полетное задание' in r_wp.text):
                return sess, r_wp.text
            else:
                last_err = "Неверный логин или пароль Web Meridian (либо требуется одноразовый код OTP)"
        except Exception as e:
            last_err = str(e)

    raise RuntimeError(last_err)


def fetch_meridian_workplan_reports(sess, wp_initial_text, date_from_str=None, date_to_str=None, latest_only=False):
    """
    Извлекает из workplan.zul список рейсов за последние 30 дней (+60 дней вперед),
    открывает каждый электронный отчет dynamic-REP_FT_HY_v9.html и возвращает их HTML.
    """
    dtid = extract_zk_dtid(wp_initial_text)
    widgets = find_zk_widgets(wp_initial_text)
    if not dtid:
        return [], []

    # Находим все иконки отчетов "Полетное задание" (zul.wgt.Image с tooltiptext "Полетное задание...")
    report_img_uuids = []
    for w in widgets:
        if 'Image' in w['type'] and ('Полетное задание' in w['props_raw'] or 'flightTask' in w['props_raw']):
            report_img_uuids.append(w['uuid'])

    # Также извлекаем даты и мертвые головы ([пас] / Пассажир по заданию) из текста страницы
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

    if latest_only and report_img_uuids:
        report_img_uuids = [report_img_uuids[-1]]

    html_reports = []
    au_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://faps.uzairways.com',
        'Referer': f"{MERIDIAN_BASE_URL}/workplan.zul"
    }

    for idx, img_uuid in enumerate(report_img_uuids):
        try:
            au_payload = {
                'dtid': dtid,
                'cmd_0': 'onClick',
                'uuid_0': img_uuid,
                'data_0': json.dumps({"pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10})
            }
            r_click = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=20)
            if not r_click.ok:
                continue

            # Ищем ссылку на dynamic-REP_FT_HY_v9.html в ответе ZK
            iframe_m = re.search(r"(/web\.meridian/reports/dynamic-html/[^'\"\\]+\.html)", r_click.text)
            if not iframe_m:
                continue

            report_url = "https://faps.uzairways.com" + iframe_m.group(1)
            r_rep = sess.get(report_url, timeout=20)
            if r_rep.ok and ('flightCrew' in r_rep.text or 'Flight Task Report' in r_rep.text):
                # Если задан фильтр дат date_from_str..date_to_str, проверяем дату отчета
                if date_from_str and date_to_str:
                    fd_m = re.search(r'data-key="flightDate"[^>]*>(\d{2})\.(\d{2})\.(\d{4})<', r_rep.text)
                    if fd_m:
                        rep_ymd = f"{fd_m.group(3)}-{fd_m.group(2)}-{fd_m.group(1)}"
                        if not (date_from_str <= rep_ymd <= date_to_str):
                            continue
                html_reports.append(r_rep.text)
        except Exception:
            continue

    return html_reports, deadhead_dates


def parse_zk_pft_rows(zk_text):
    """
    Извлекает строки правой таблицы рейсов из ответа personalFlightTime.zul (по 9 ячеек на рейс).
    """
    widgets = find_zk_widgets(zk_text)
    labels = []
    for w in widgets:
        if 'Label' in w['type']:
            val_m = re.search(r"value\s*:\s*['\"]([^'\"]*)['\"]", w['props_raw'])
            if val_m:
                labels.append(val_m.group(1).strip())

    rows = []
    date_rx = re.compile(r"^\d{2}\s+[а-яёА-ЯЁ]{3}[а-яёА-ЯЁ\.]*\s+\d{4}$")
    i = 0
    while i < len(labels) - 8:
        if date_rx.match(labels[i]):
            row = labels[i:i+9]
            rows.append(row)
            i += 9
        else:
            i += 1
    return rows


def fetch_meridian_personal_flight_time(sess, date_from_str, date_to_str):
    """
    Заходит в personalFlightTime.zul, переключает нужные месяцы из диапазона date_from_str..date_to_str
    и возвращает список всех строк таблицы Персонального налета.
    """
    r_pft = sess.get(f"{MERIDIAN_BASE_URL}/personalFlightTime.zul", timeout=20)
    if not r_pft.ok:
        return []

    dtid = extract_zk_dtid(r_pft.text)
    widgets = find_zk_widgets(r_pft.text)
    if not dtid:
        return []

    # Определяем, какие месяцы ("август 2026", "сентябрь 2026"...) входят в запрошенный диапазон
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

    # Находим в дереве виджетов listbox месяцев и listitem каждого месяца
    listboxes = [w for w in widgets if 'Listbox' in w['type']]
    months_listbox_uuid = listboxes[0]['uuid'] if listboxes else None

    # Сопоставляем каждый Listitem месяца с его текстовой меткой ("август 2026")
    month_item_uuids = []
    last_listitem_uuid = None
    for w in widgets:
        if 'Listitem' in w['type']:
            last_listitem_uuid = w['uuid']
        elif 'Label' in w['type'] and last_listitem_uuid:
            val_m = re.search(r"value\s*:\s*['\"]([^'\"]+)['\"]", w['props_raw'])
            if val_m:
                lbl_val = val_m.group(1).strip().lower()
                if lbl_val in target_month_labels:
                    month_item_uuids.append((lbl_val, last_listitem_uuid))
                    last_listitem_uuid = None

    all_rows = []
    # Сначала парсим уже открытый по умолчанию месяц
    initial_rows = parse_zk_pft_rows(r_pft.text)
    all_rows.extend(initial_rows)

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
                        "clearFirst": False,
                        "selectAll": False,
                        "pageX": 15,
                        "pageY": 15,
                        "which": 1,
                        "x": 15,
                        "y": 15
                    })
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
    return "Гибридный мост Flight Log v3.1.0 (Web Meridian + Почта Exchange + Расчетные листки) работает штатно!"


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
                # Если в Плане работ еще нет закрытого отчета — переключаемся на почту ниже
            elif action == 'meridian_range' and date_from_str and date_to_str:
                today_dt = datetime.now()
                cutoff_30d = (today_dt - timedelta(days=30)).strftime('%Y-%m-%d')

                html_reports = []
                deadhead_dates = []
                pft_rows = []

                # 1. Если диапазон затрагивает последние 30 дней (+60 дней вперед) — берем полные отчеты из Плана работ
                if date_to_str >= cutoff_30d:
                    html_reports, deadhead_dates = fetch_meridian_workplan_reports(
                        sess, wp_text, date_from_str=date_from_str, date_to_str=date_to_str, latest_only=False
                    )

                # 2. Если начальная дата старше 30 дней — мгновенно забираем таблицу из Персонального налета
                if date_from_str < cutoff_30d:
                    pft_rows = fetch_meridian_personal_flight_time(sess, date_from_str, date_to_str)

                return jsonify({
                    "mode": "meridian_range",
                    "htmlReports": html_reports,
                    "deadheadDates": deadhead_dates,
                    "pftRows": pft_rows,
                    "needsBackgroundMailSync": bool(date_from_str < cutoff_30d)
                })
        except Exception as mer_err:
            # Если сайт Web Meridian недоступен и запрашивался крайний рейс — идем на почту
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
