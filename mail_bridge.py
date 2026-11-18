import os
import re
import json
import time
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
# КЛИЕНТ WEB MERIDIAN (ZK 10.2.1 AU ПРОТОКОЛ С ПОДДЕРЖКОЙ ZUL.UTL.TIMER / ECHO)
# ==============================================================================

def normalize_zk_text(text):
    """Декодирует \\\\uXXXX, \\uXXXX, \\xXX, \\-, \\' и \\/ в ответах ZK zkmx и zkau."""
    if not text:
        return ""
    s = re.sub(r'\\\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
    s = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)
    s = s.replace(r'\-', '-').replace(r'\/', '/').replace(r"\'", "'").replace(r'\"', '"')
    return s

def extract_zk_dtid_and_prefix(raw_text):
    text = normalize_zk_text(raw_text)
    dtid = None
    for pat in [
        r"['\"]?dt['\"]?\s*:\s*['\"]([^'\"]+)['\"]",
        r"/zkau/view/([^/\"']+)/",
        r"dtid\s*[=:]\s*['\"]([^'\"]+)['\"]"
    ]:
        m = re.search(pat, text)
        if m:
            dtid = m.group(1).replace('\\', '').strip()
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


def extract_timers_and_echos(raw_text, pfx=None, default_timer_uuid=None, force_default=False, debug_log=None, include_repeating_timers=False):
    """
    Извлекает все команды echo/echo2 ВМЕСТЕ с их 3-м аргументом data (если он передан сервером!)
    и активные таймеры zul.utl.Timer как из HTML (zkmx), так и из JSON-ответов (/zkau).
    Возвращает: (timers_list, echos_list), где каждый элемент echos_list = (uuid, evt_name, has_data, data_val).
    """
    text = normalize_zk_text(raw_text)
    timers = []
    echos = []
    seen_echo_keys = set()

    # 1. Точный JSON-разбор ответа /zkau (сохраняет 3-й аргумент data в ["echo2", [{"$u": ...}, "evt", data]])
    stripped = raw_text.strip() if isinstance(raw_text, str) else ""
    if stripped.startswith('{') and '"rs"' in stripped:
        try:
            parsed_json = json.loads(stripped)
            for cmd_entry in parsed_json.get('rs', []):
                if isinstance(cmd_entry, list) and len(cmd_entry) >= 2:
                    c_name = cmd_entry[0]
                    c_args = cmd_entry[1]
                    if c_name in ('echo', 'echo2') and isinstance(c_args, list) and len(c_args) >= 2:
                        t_obj = c_args[0]
                        t_uuid = t_obj.get('$u') if isinstance(t_obj, dict) else str(t_obj)
                        e_name = str(c_args[1])
                        has_d = (len(c_args) >= 3)
                        d_val = c_args[2] if has_d else None
                        if t_uuid and e_name:
                            ekey = f"{t_uuid}:{e_name}:{json.dumps(d_val, ensure_ascii=False, sort_keys=True) if has_d else 'NO_DATA'}"
                            if ekey not in seen_echo_keys:
                                seen_echo_keys.add(ekey)
                                echos.append((t_uuid, e_name, has_d, d_val))
                    elif c_name in ('setAttr', 'invoke') and isinstance(c_args, list) and len(c_args) >= 3:
                        t_obj = c_args[0]
                        t_uuid = t_obj.get('$u') if isinstance(t_obj, dict) else None
                        if t_uuid and c_args[1] in ('running', 'play') and c_args[2] is True:
                            if t_uuid not in timers:
                                timers.append(t_uuid)
        except Exception:
            pass

    # 2. Разбор виджетов zul.utl.Timer
    widgets = find_zk_widgets(text)
    for w in widgets:
        if 'Timer' in w['type']:
            u = w['uuid']
            props = w['props_raw'].replace(' ', '')
            if 'running:false' in props:
                continue
            if "id:'timer'" in props or 'id:"timer"' in props or 'delay:60000' in props or 'delay:30000' in props:
                continue
            if not include_repeating_timers and 'repeats:true' in props and ('delay:60000' in props or 'delay:30000' in props):
                continue
            if u not in timers:
                timers.append(u)

    # 3. Резервный поиск echo/echo2 в тексте (например внутри HTML zkmx или склеенных пакетов)
    for em in re.finditer(r"""['"]echo2?['"]\s*,\s*\[\s*(?:\{\s*['"]?\$u['"]?\s*:\s*)?['"]([a-zA-Z0-9_]+)['"]\s*\}?\s*,\s*['"]([^'"]+)['"](?:\s*,\s*([^\]]+))?\s*\]""", text):
        t_uuid, e_name, raw_third = em.group(1), em.group(2), em.group(3)
        if any(x[0] == t_uuid and x[1] == e_name for x in echos):
            continue
        has_d = False
        d_val = None
        if raw_third is not None and raw_third.strip() != "":
            has_d = True
            rt = raw_third.strip()
            try:
                d_val = json.loads(rt)
            except Exception:
                d_val = rt.strip("'\"")
        ekey = f"{t_uuid}:{e_name}:{json.dumps(d_val, ensure_ascii=False, sort_keys=True) if has_d else 'NO_DATA'}"
        if ekey not in seen_echo_keys:
            seen_echo_keys.add(ekey)
            echos.append((t_uuid, e_name, has_d, d_val))

    for tm in re.finditer(r"""\{\s*['"]?\$u['"]?\s*:\s*['"]([a-zA-Z0-9_]+)['"]\s*\}\s*,\s*['"](?:running|play)['"]\s*,\s*true""", text):
        u = tm.group(1)
        if u not in timers:
            timers.append(u)

    if debug_log is not None:
        if echos:
            short_e = [(u, en, d if hd else 'no3rd') for (u, en, hd, d) in echos]
            debug_log.append(f"echos: {short_e}")
        if timers:
            debug_log.append(f"timers: {timers}")

    return timers, echos


def pump_zk_timers(sess, dtid, pfx, raw_text, referer_url, debug_log=None, step_label="pump", default_timer_uuid=None, force_default=False, include_repeating_timers=False):
    """
    Отправляет события echo/echo2 (с сохранением точного 3-го аргумента data!) и cmd_0=onTimer,
    дожидаясь завершения фоновых задач ZK и генерации таблиц или dynamic-html отчета.
    """
    if debug_log is None:
        debug_log = []

    au_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://faps.uzairways.com',
        'Referer': referer_url
    }

    combined = normalize_zk_text(raw_text)
    current_inputs = [raw_text]
    executed_echos = set()
    known_timers = []

    for pass_idx in range(6):
        timers = []
        echos = []
        for inp in current_inputs:
            t_list, e_list = extract_timers_and_echos(
                inp,
                pfx=pfx,
                default_timer_uuid=default_timer_uuid,
                force_default=False,
                debug_log=debug_log if pass_idx == 0 else None,
                include_repeating_timers=include_repeating_timers
            )
            for tu in t_list:
                if tu not in timers:
                    timers.append(tu)
            for eo in e_list:
                if eo not in echos:
                    echos.append(eo)

        for tu in timers:
            if tu not in known_timers:
                known_timers.append(tu)

        pending_echos = []
        for (tu, en, hd, dv) in echos:
            ekey = f"{tu}:{en}:{json.dumps(dv, ensure_ascii=False, sort_keys=True) if hd else 'NO_DATA'}"
            if ekey not in executed_echos:
                pending_echos.append((ekey, tu, en, hd, dv))

        if not known_timers and not pending_echos:
            break

        got_meaningful_data = False
        next_step_raws = []

        for (ekey, target_u, evt_name, has_data, data_val) in pending_echos:
            executed_echos.add(ekey)
            # В ZK JS AuCmd0.echo2: data != null ? {'': data} : null
            if has_data and data_val is not None:
                echo_payload_json = json.dumps({"": data_val})
            else:
                echo_payload_json = json.dumps({"": None})

            au_payload = {
                'dtid': dtid,
                'cmd_0': evt_name,
                'uuid_0': target_u,
                'data_0': echo_payload_json
            }
            r_echo = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=30)
            raw_resp = r_echo.text if r_echo.ok else ""
            echo_norm = normalize_zk_text(raw_resp)
            if len(echo_norm) < 220:
                short_preview = f", resp={echo_norm[:130]}"
            else:
                short_preview = f", listitem={'Listitem' in echo_norm}, html={'dynamic-html' in echo_norm}"
            debug_log.append(f"{step_label} echo({target_u},{evt_name}): len={len(echo_norm)}{short_preview}")
            if len(echo_norm) > 20:
                combined += "\n" + echo_norm
                next_step_raws.append(raw_resp)
                got_meaningful_data = True
                new_t, _ = extract_timers_and_echos(raw_resp, pfx=pfx, include_repeating_timers=include_repeating_timers)
                for ntu in new_t:
                    if ntu not in known_timers:
                        known_timers.append(ntu)

        if 'dynamic-html' in combined:
            break

        for t_uuid in list(known_timers):
            for poll_idx in range(10):
                au_payload = {
                    'dtid': dtid,
                    'cmd_0': 'onTimer',
                    'uuid_0': t_uuid,
                    'data_0': json.dumps({"": None})
                }
                r_pump = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=au_payload, headers=au_headers, timeout=20)
                raw_pump = r_pump.text if r_pump.ok else ""
                pump_norm = normalize_zk_text(raw_pump)
                if len(pump_norm) < 220:
                    short_preview = f", resp={pump_norm[:120]}"
                else:
                    short_preview = f", listitem={'Listitem' in pump_norm}, html={'dynamic-html' in pump_norm}"
                debug_log.append(f"{step_label} onTimer({t_uuid})#{poll_idx}: len={len(pump_norm)}{short_preview}")
                if len(pump_norm) > 20:
                    combined += "\n" + pump_norm
                    next_step_raws.append(raw_pump)
                    got_meaningful_data = True
                if 'dynamic-html' in pump_norm or 'Listitem' in pump_norm:
                    if t_uuid in known_timers:
                        known_timers.remove(t_uuid)
                    break
                if re.search(r"['\"]running['\"]\s*,\s*false", pump_norm):
                    if t_uuid in known_timers:
                        known_timers.remove(t_uuid)
                    break
                _, sub_echos = extract_timers_and_echos(raw_pump, pfx=pfx, include_repeating_timers=include_repeating_timers)
                if sub_echos:
                    break
                time.sleep(0.4)

        if not got_meaningful_data:
            break
        current_inputs = next_step_raws
        if 'dynamic-html' in combined:
            break

    return combined


def meridian_login_session(email_or_login, password, debug_log=None):
    """
    Авторизуется на https://faps.uzairways.com/web.meridian/login.zul
    и обязательно переходит по редиректу /web.meridian/welcome.zul для фиксации сессии.
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

            # Обязательно выполняем GET welcome.zul, чтобы завершить редирект ZK после авторизации
            r_wel = sess.get(f"{MERIDIAN_BASE_URL}/welcome.zul", timeout=18)
            debug_log.append(f"GET welcome.zul: status={r_wel.status_code}, url={r_wel.url}")
            if r_wel.ok and 'login.zul' not in r_wel.url:
                return sess
            else:
                last_err = f"Неверный логин или пароль Web Meridian (ответ: {au_norm[:120]})"
        except Exception as e:
            last_err = str(e)
            debug_log.append(f"Exception ({login_candidate}): {last_err}")

    raise RuntimeError(last_err)


def has_executed_legs_in_html(html_text):
    for m in re.finditer(r'<[^>]*\bdata-key=["\'](?:totalTime|flighting)["\'][^>]*>', html_text):
        tag_str = m.group(0)
        for t_val in re.findall(r'\b(\d{2}:\d{2})\b', tag_str):
            if t_val != '00:00':
                return True
    return False


def is_pilot_deadhead_in_report(html_text, email_or_login=""):
    if not email_or_login:
        return False
    local_part = email_or_login.split('@')[0].upper()
    tokens = [t for t in re.split(r'[._\-]+', local_part) if len(t) >= 3]
    if not tokens:
        return False

    fc_m = re.search(r'data-key=["\']flightCrew["\']([\s\S]*?)(?:data-key=["\'](?:cabinCrew|extraCrew|otherCrew)["\']|FLIGHT\s+REPORT)', html_text, re.I)
    ec_m = re.search(r'data-key=["\']extraCrew["\']([\s\S]*?)(?:data-key=["\']otherCrew["\']|MEDICAL\s+CHECK|FLIGHT\s+REPORT)', html_text, re.I)

    fc_text = (fc_m.group(1) if fc_m else "").upper()
    ec_text = (ec_m.group(1) if ec_m else "").upper()

    in_cockpit = any(tok in fc_text for tok in tokens)
    in_dh = any(tok in ec_text for tok in tokens)

    aug_m = re.findall(r'data-key=["\']augmentCrew["\']([\s\S]{0,4000}?)</div>\s*</div>\s*</div>', html_text, re.I)
    aug_text = " ".join(aug_m).upper()
    in_aug = any(tok in aug_text for tok in tokens)

    if in_dh and not in_cockpit and not in_aug:
        return True
    return False


def extract_report_flight_date(html_text):
    m = re.search(r'data-key=["\']flightDate["\'][^>]*>\s*(\d{2})\.(\d{2})\.(\d{4})\s*<', html_text)
    if m:
        dd, mm, yyyy = m.group(1), m.group(2), m.group(3)
        return f"{dd}.{mm}.{yyyy}", f"{yyyy}-{mm}-{dd}"
    return None, None


def extract_wp_table_dates(zk_text):
    dates = []
    for dm in re.finditer(r"(?:value|label)\s*:\s*['\"](\d{2})\.(\d{2})\.(\d{4})\s*\(", zk_text):
        ymd = f"{dm.group(3)}-{dm.group(2)}-{dm.group(1)}"
        if ymd not in dates:
            dates.append(ymd)
    return dates


def extract_zk_listen_events(props_raw):
    """Извлекает все серверные события вида $onClick:true / $$0onCustom:true из свойств виджета ZK."""
    evts = []
    for m in re.finditer(r"\$+(?:0|1)?(on[A-Z][a-zA-Z0-9_]*)\s*:\s*true", props_raw or ""):
        ev = m.group(1)
        if ev not in evts:
            evts.append(ev)
    return evts


def build_datebox_candidate_payloads(target_dt, props_raw=""):
    """
    Формирует кандидаты data_0 для Datebox в ZK 9.6 / 10 (jq.j2d / jq.d2j),
    начиная с точного полуночного формата 'YYYY.M.D.0.0.0.0' без часов/секунд.
    """
    y, m, d = target_dt.year, target_dt.month, target_dt.day
    candidates = [
        {"value": f"{y}.{m}.{d}.0.0.0.0"},
        {"value": target_dt.strftime("%Y.%m.%d.0.0.0.0")},
        {"value": target_dt.strftime("%d.%m.%Y")},
        {"value": f"{y}.{m - 1}.{d}.0.0.0.0"},
        {"fval": target_dt.strftime("%d.%m.%Y"), "value": f"{y}.{m}.{d}.0.0.0.0"}
    ]
    return candidates


def parse_workplan_rows_and_icons(zk_text, email_or_login="", debug_log=None):
    """
    Разбирает таблицу workplan.zul и для каждой иконки отчета Полетное задание ($report.data.flightTask)
    захватывает её непосредственный родительский виджет (z-macro = widgets[idx - 1]) и все виджеты вокруг неё,
    у которых в props_raw зарегистрирован серверный слушатель $onClick:true / $on...:true!
    """
    widgets = find_zk_widgets(zk_text)
    deadhead_dates = []
    flight_rows = []
    report_icons = []
    seen_icon_uuids = set()

    current_listitem_uuid = None
    current_date_str = None
    current_date_ymd = None
    current_row_obj = None

    for idx_w, w in enumerate(widgets):
        if 'Listitem' in w['type']:
            current_listitem_uuid = w['uuid']
            current_row_obj = None
        elif 'Label' in w['type'] or 'Listcell' in w['type']:
            val_m = re.search(r"(?:value|label)\s*:\s*['\"]([^'\"]+)['\"]", w['props_raw'])
            if val_m:
                v = val_m.group(1).strip()
                dm = re.match(r"^(\d{2})\.(\d{2})\.(\d{4})\s*\(", v)
                if dm:
                    current_date_str = f"{dm.group(1)}.{dm.group(2)}.{dm.group(3)}"
                    current_date_ymd = f"{dm.group(3)}-{dm.group(2)}-{dm.group(1)}"
                elif current_row_obj is not None and re.match(r"^HY\s*\d+$", v):
                    current_row_obj['flight_no'] = v.replace(" ", "")
                elif '[пас]' in v and current_date_str:
                    is_bold_self = ('bold' in w['props_raw'])
                    if not is_bold_self and email_or_login:
                        local_part = email_or_login.split('@')[0].lower()
                        tokens = [t for t in re.split(r'[._\-]+', local_part) if len(t) >= 3]
                        if tokens and any(t in v.lower() for t in tokens):
                            is_bold_self = True
                    if is_bold_self and current_date_str not in deadhead_dates:
                        deadhead_dates.append(current_date_str)
        elif 'Image' in w['type']:
            props_low = w['props_raw'].lower().replace('ё', 'е')
            if 'workplan-leg.png' in props_low and current_listitem_uuid:
                if not flight_rows or flight_rows[-1]['row_uuid'] != current_listitem_uuid:
                    current_row_obj = {
                        'row_uuid': current_listitem_uuid,
                        'date_ymd': current_date_ymd,
                        'date_str': current_date_str,
                        'flight_no': ''
                    }
                    flight_rows.append(current_row_obj)
            elif ('полетное задание' in props_low or 'flighttask' in props_low or 'flight_task' in props_low):
                if w['uuid'] not in seen_icon_uuids:
                    seen_icon_uuids.add(w['uuid'])
                    parent_w = widgets[idx_w - 1] if idx_w >= 1 else None
                    grand_w = widgets[idx_w - 2] if idx_w >= 2 else None

                    # Собираем кандидаты (uuid, events) в окрестности иконки: сначала те, где явно есть $onClick:true!
                    click_chain = []
                    for nb in [parent_w, w, grand_w]:
                        if nb is None:
                            continue
                        evts = extract_zk_listen_events(nb['props_raw'])
                        click_chain.append({
                            'uuid': nb['uuid'],
                            'type': nb['type'],
                            'events': evts,
                            'props_short': nb['props_raw'][:110]
                        })

                    # Сортируем так, чтобы виджеты с явным серверным слушателем ($onClick и др.) шли первыми
                    click_chain.sort(key=lambda item: (0 if item['events'] else 1))

                    if debug_log is not None and len(report_icons) == 0:
                        summary_nb = [f"{c['type'].split('.')[-1]}:{c['uuid']}(ev={c['events']},p={c['props_short'][:70]})" for c in click_chain[:2]]
                        debug_log.append(f"icon0_tree: {' | '.join(summary_nb)}")

                    report_icons.append({
                        'img_uuid': w['uuid'],
                        'macro_uuid': parent_w['uuid'] if parent_w else None,
                        'click_chain': click_chain,
                        'inline_row_uuid': current_listitem_uuid
                    })

    return flight_rows, report_icons, deadhead_dates


def try_click_icon_chain(sess, dtid, pfx, click_chain, au_headers, debug_log, step_tag):
    """Пробует кликнуть по макросу/иконке отчета (включая все найденные серверные события $on...) и прокачать таймеры модального окна."""
    combined = ""
    tried = set()
    for item in click_chain:
        c_uuid = item['uuid']
        ev_list = item['events'] if item['events'] else ['onClick']
        for ev_name in ev_list:
            if (c_uuid, ev_name) in tried:
                continue
            tried.add((c_uuid, ev_name))
            payload_data = {"pageX": 10, "pageY": 10, "which": 1, "x": 10, "y": 10} if 'Click' in ev_name else {"": None}
            r_ic = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data={
                'dtid': dtid,
                'cmd_0': ev_name,
                'uuid_0': c_uuid,
                'data_0': json.dumps(payload_data)
            }, headers=au_headers, timeout=20)
            raw_ic = r_ic.text if r_ic.ok else ""
            ic_norm = normalize_zk_text(raw_ic)
            debug_log.append(f"{step_tag}({c_uuid},{ev_name}): len={len(ic_norm)}, resp={ic_norm[:130]}")
            if len(ic_norm) > 22 and '"alert"' not in ic_norm:
                pumped = pump_zk_timers(
                    sess, dtid, pfx, raw_ic,
                    referer_url=f"{MERIDIAN_BASE_URL}/workplan.zul",
                    debug_log=debug_log,
                    step_label=f"{step_tag}_m",
                    include_repeating_timers=True
                )
                combined += "\n" + pumped
                if 'dynamic-html' in combined:
                    return combined
    return combined


def close_zk_modal_windows(sess, dtid, zk_text, au_headers):
    modal_wins = [w['uuid'] for w in find_zk_widgets(zk_text) if 'Window' in w['type'] and 'modal' in w['props_raw']]
    for mw_uuid in modal_wins:
        try:
            sess.post(f"{MERIDIAN_BASE_URL}/zkau", data={
                'dtid': dtid,
                'cmd_0': 'onClose',
                'uuid_0': mw_uuid,
                'data_0': json.dumps({})
            }, headers=au_headers, timeout=10)
        except Exception:
            pass


def open_workplan_row_report(sess, dtid, pfx, listbox_uuid, ft_btn_uuid, row_target, au_headers, debug_log, idx_t=0):
    """
    Открывает отчет Полетного задания для строки рейса:
    Фаза А: Сразу кликает по родительскому макросу z-macro (widgets[i-1]) иконки отчета ВНУТРИ строки
            ДО вызова onSelect (пока начальные UUID не уничтожены командой rm!).
    Фаза Б: Если Фаза А не дала dynamic-html — выделяет строку рейса (onSelect),
            выполняет onSearchItemReportsEvent с полным 3-м аргументом data,
            извлекает НОВЫЙ макрос z-macro из ответа выделения строки и кликает по нему.
    """
    combined_modal = ""

    # ФАЗА А: Прямой клик по макросу z-macro иконки отчета (до onSelect!)
    if row_target.get('click_chain'):
        combined_modal += "\n" + try_click_icon_chain(
            sess, dtid, pfx, row_target['click_chain'],
            au_headers=au_headers, debug_log=debug_log, step_tag=f"wp_macA#{idx_t}"
        )

    # ФАЗА Б: Выделение строки -> echo2(onSearchItemReportsEvent с 3-м аргументом) -> клик по новому макросу строки
    row_uuid = row_target.get('row_uuid')
    if 'dynamic-html' not in combined_modal and listbox_uuid and row_uuid:
        sel_data = {
            'dtid': dtid,
            'cmd_0': 'onSelect',
            'uuid_0': listbox_uuid,
            'data_0': json.dumps({
                "items": [row_uuid],
                "reference": row_uuid,
                "clearFirst": True,
                "selectAll": False,
                "pageX": 40, "pageY": 15, "which": 1, "x": 40, "y": 15
            }),
            'cmd_1': 'onClick',
            'uuid_1': row_uuid,
            'data_1': json.dumps({"pageX": 40, "pageY": 15, "which": 1, "x": 40, "y": 15})
        }
        r_sel = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=sel_data, headers=au_headers, timeout=20)
        raw_sel = r_sel.text if r_sel.ok else ""
        sel_norm = normalize_zk_text(raw_sel)
        debug_log.append(f"wp_sel#{idx_t}({row_uuid},{row_target.get('date_ymd')},{row_target.get('flight_no','')}): len={len(sel_norm)}")

        after_sel = pump_zk_timers(
            sess, dtid, pfx, raw_sel,
            referer_url=f"{MERIDIAN_BASE_URL}/workplan.zul",
            debug_log=debug_log,
            step_label=f"wp_sel_e#{idx_t}",
            include_repeating_timers=False
        )
        combined_modal += "\n" + after_sel

        if 'dynamic-html' not in combined_modal:
            _, refreshed_icons, _ = parse_workplan_rows_and_icons(after_sel)
            for r_ic_obj in refreshed_icons:
                combined_modal += "\n" + try_click_icon_chain(
                    sess, dtid, pfx, r_ic_obj['click_chain'],
                    au_headers=au_headers, debug_log=debug_log, step_tag=f"wp_macB#{idx_t}"
                )
                if 'dynamic-html' in combined_modal:
                    break

    close_zk_modal_windows(sess, dtid, combined_modal, au_headers)

    iframe_m = re.search(r"((?:/web\.meridian/)?reports/dynamic-html/[^'\"\s<>]+\.html[^'\"\s<>]*)", combined_modal)
    if iframe_m:
        rel_path = iframe_m.group(1)
        if not rel_path.startswith('/'):
            rel_path = '/web.meridian/' + rel_path
        return "https://faps.uzairways.com" + rel_path
    return None


def fetch_meridian_workplan_reports(sess, date_from_str=None, date_to_str=None, latest_only=False, debug_log=None, email_or_login=""):
    if debug_log is None:
        debug_log = []

    r_wp = sess.get(f"{MERIDIAN_BASE_URL}/workplan.zul", timeout=20)
    if not r_wp.ok or 'login.zul' in r_wp.url:
        debug_log.append(f"GET workplan.zul failed: status={r_wp.status_code}, url={r_wp.url}")
        return [], []

    wp_initial_text = normalize_zk_text(r_wp.text)
    dtid, pfx = extract_zk_dtid_and_prefix(wp_initial_text)
    init_widgets = find_zk_widgets(wp_initial_text)
    debug_log.append(f"wp init: dtid={dtid}, pfx={pfx}")
    if not dtid:
        return [], []

    au_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://faps.uzairways.com',
        'Referer': f"{MERIDIAN_BASE_URL}/workplan.zul"
    }

    page_timer_uuid = f"{pfx}02" if pfx else None

    # ШАГ 1: Загружаем стартовую таблицу Плана работ (передаем сырой r_wp.text для точного разбора echo2)
    combined_wp_text = pump_zk_timers(
        sess, dtid, pfx, r_wp.text,
        referer_url=f"{MERIDIAN_BASE_URL}/workplan.zul",
        debug_log=debug_log,
        step_label="wp_init",
        default_timer_uuid=page_timer_uuid,
        force_default=False
    )

    init_dates = extract_wp_table_dates(combined_wp_text)
    init_min_date = min(init_dates) if init_dates else datetime.now().strftime('%Y-%m-%d')
    all_init_widgets = find_zk_widgets(combined_wp_text)

    dateboxes = [w for w in all_init_widgets if 'Datebox' in w['type']]
    datebox_from_uuid = dateboxes[0]['uuid'] if dateboxes else (f"{pfx}52" if pfx else None)
    datebox_from_props = dateboxes[0]['props_raw'] if dateboxes else ""

    buttons = [w for w in all_init_widgets if 'Button' in w['type'] or 'Toolbarbutton' in w['type']]
    refresh_btn = next((w for w in buttons if 'Обновить' in w['props_raw'] or 'refresh' in w['props_raw'].lower()), None)
    refresh_btn_uuid = refresh_btn['uuid'] if refresh_btn else (f"{pfx}92" if pfx else None)

    active_table_text = combined_wp_text

    # ШАГ 2: Сдвиг Datebox на -29 дней для загрузки за период (с сохранением полной подсказки формата в pinned-строке!)
    if not latest_only and datebox_from_uuid and refresh_btn_uuid:
        target_start_dt = datetime.now() - timedelta(days=29)
        if date_from_str:
            try:
                req_dt = datetime.strptime(date_from_str, '%Y-%m-%d')
                if req_dt > target_start_dt:
                    target_start_dt = req_dt
            except Exception:
                pass

        if target_start_dt.strftime('%Y-%m-%d') < init_min_date:
            cand_payloads = build_datebox_candidate_payloads(target_start_dt, datebox_from_props)
            logged_wrong_msg = False
            accepted_date = False

            for idx_fmt, date_payload in enumerate(cand_payloads):
                try:
                    r_chg = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data={
                        'dtid': dtid,
                        'cmd_0': 'onChange',
                        'uuid_0': datebox_from_uuid,
                        'data_0': json.dumps(date_payload)
                    }, headers=au_headers, timeout=15)
                    if not r_chg.ok:
                        continue
                    chg_norm = normalize_zk_text(r_chg.text)
                    if 'wrongValue' in chg_norm or 'Illegal' in chg_norm or 'exception' in chg_norm.lower():
                        if not logged_wrong_msg:
                            # Помечаем PIN:, чтобы фронтенд всегда закреплял эту строку сверху лога без обрезки!
                            debug_log.append(f"PIN:date_err#{idx_fmt}: {chg_norm[:250]}")
                            logged_wrong_msg = True
                        continue

                    debug_log.append(f"PIN:date_ok#{idx_fmt}({json.dumps(date_payload)}): {chg_norm[:110]}")
                    accepted_date = True
                    break
                except Exception as e:
                    debug_log.append(f"PIN:date_exc#{idx_fmt}: {e}")

            if accepted_date:
                try:
                    r_ref = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data={
                        'dtid': dtid,
                        'cmd_0': 'onClick',
                        'uuid_0': refresh_btn_uuid,
                        'data_0': json.dumps({"pageX": 15, "pageY": 12, "which": 1, "x": 15, "y": 12})
                    }, headers=au_headers, timeout=20)
                    if r_ref.ok:
                        ref_norm = normalize_zk_text(r_ref.text)
                        if 'wrongValue' not in ref_norm:
                            pumped_ref = pump_zk_timers(
                                sess, dtid, pfx, r_ref.text,
                                referer_url=f"{MERIDIAN_BASE_URL}/workplan.zul",
                                debug_log=debug_log,
                                step_label="wp_ref",
                                default_timer_uuid=page_timer_uuid,
                                force_default=False
                            )
                            if 'Listitem' in pumped_ref:
                                active_table_text = pumped_ref
                except Exception as e:
                    debug_log.append(f"wp_ref err: {e}")

    icon_tree_logs = []
    flight_rows, report_icons, deadhead_dates = parse_workplan_rows_and_icons(
        active_table_text, email_or_login=email_or_login, debug_log=icon_tree_logs
    )
    for il in icon_tree_logs:
        debug_log.append(f"PIN:{il}")

    active_dates = extract_wp_table_dates(active_table_text)
    debug_log.append(f"PIN:wp_tbl: dates={active_dates[:2]}..{active_dates[-1:]}, rows={len(flight_rows)}, icons={len(report_icons)}")

    # Собираем цели ТОЛЬКО по реально существующим иконкам отчетов (чтобы не тратить время на будущие рейсы без отчетов, такие как 18.11 HY574)
    report_targets = []
    for idx_i, icon_obj in enumerate(report_icons):
        paired_row = flight_rows[idx_i] if idx_i < len(flight_rows) else {'row_uuid': icon_obj['inline_row_uuid'], 'date_ymd': None, 'flight_no': ''}
        t_item = dict(paired_row)
        t_item['img_uuid'] = icon_obj['img_uuid']
        t_item['macro_uuid'] = icon_obj['macro_uuid']
        t_item['click_chain'] = icon_obj['click_chain']
        report_targets.append(t_item)

    min_ymd = None
    max_ymd = None
    if date_from_str and date_to_str:
        try:
            min_ymd = (datetime.strptime(date_from_str, '%Y-%m-%d') - timedelta(days=2)).strftime('%Y-%m-%d')
            max_ymd = (datetime.strptime(date_to_str, '%Y-%m-%d') + timedelta(days=2)).strftime('%Y-%m-%d')
        except Exception:
            pass

    if latest_only and report_targets:
        report_targets = list(reversed(report_targets))

    all_listboxes = [w for w in all_init_widgets if 'Listbox' in w['type']]
    wp_listboxes = [w for w in all_listboxes if 'workplan-table' in w['props_raw']]
    listbox_uuid = wp_listboxes[0]['uuid'] if wp_listboxes else (all_listboxes[0]['uuid'] if all_listboxes else (f"{pfx}g2" if pfx else None))

    ft_btn = next((w for w in buttons if 'Полетное задание' in w['props_raw'] or 'FT' in w['props_raw']), None)
    ft_btn_uuid = ft_btn['uuid'] if ft_btn else (f"{pfx}u2" if pfx else None)

    html_reports = []
    for idx_t, target in enumerate(report_targets):
        if not latest_only and min_ymd and max_ymd and target.get('date_ymd'):
            if not (min_ymd <= target['date_ymd'] <= max_ymd):
                continue

        try:
            report_url = open_workplan_row_report(
                sess, dtid, pfx, listbox_uuid, ft_btn_uuid,
                row_target=target, au_headers=au_headers,
                debug_log=debug_log, idx_t=idx_t
            )
            if not report_url:
                debug_log.append(f"wp_row#{idx_t}: no dynamic-html")
                continue

            r_rep = sess.get(report_url, timeout=20)
            if r_rep.ok and ('flightCrew' in r_rep.text or 'Flight Task Report' in r_rep.text):
                rep_d_str, rep_d_ymd = extract_report_flight_date(r_rep.text)
                debug_log.append(f"wp_row#{idx_t} GOT HTML ({rep_d_str}): len={len(r_rep.text)}")

                if is_pilot_deadhead_in_report(r_rep.text, email_or_login):
                    if rep_d_str and rep_d_str not in deadhead_dates:
                        deadhead_dates.append(rep_d_str)
                    debug_log.append(f"wp_row#{idx_t} ({rep_d_str}): skipped D/H")
                    continue

                if not latest_only and min_ymd and max_ymd and rep_d_ymd:
                    if not (min_ymd <= rep_d_ymd <= max_ymd):
                        continue

                if latest_only:
                    if has_executed_legs_in_html(r_rep.text):
                        html_reports.append(r_rep.text)
                        break
                    else:
                        debug_log.append(f"wp_row#{idx_t} ({rep_d_str}): skipped 00:00")
                        continue
                else:
                    if r_rep.text not in html_reports:
                        html_reports.append(r_rep.text)
        except Exception as e:
            debug_log.append(f"wp_row err#{idx_t}: {e}")
            continue

    debug_log.append(f"workplan html_reports fetched: {len(html_reports)}")
    return html_reports, deadhead_dates


def parse_zk_pft_rows(raw_zk_text):
    """
    Извлекает строки правой таблицы рейсов из ответа personalFlightTime.zul.
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
    Заходит в personalFlightTime.zul, вызывает onTimer (и при необходимости нажимает кнопку Обновить <PFX>a2),
    затем выбирает нужные месяцы из левой таблицы (<PFX>d2) и возвращает все строки рейсов.
    """
    if debug_log is None:
        debug_log = []

    r_pft = sess.get(f"{MERIDIAN_BASE_URL}/personalFlightTime.zul", timeout=20)
    if not r_pft.ok or 'login.zul' in r_pft.url:
        debug_log.append(f"GET personalFlightTime.zul failed: {r_pft.status_code}, url={r_pft.url}")
        return []

    pft_norm = normalize_zk_text(r_pft.text)
    dtid, pfx = extract_zk_dtid_and_prefix(pft_norm)
    init_widgets = find_zk_widgets(pft_norm)
    debug_log.append(f"pft init: dtid={dtid}, pfx={pfx}, widgets={len(init_widgets)}")
    if not dtid:
        return []

    au_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://faps.uzairways.com',
        'Referer': f"{MERIDIAN_BASE_URL}/personalFlightTime.zul"
    }

    page_timer_uuid = f"{pfx}02" if pfx else None

    # ШАГ 1: Опрашиваем активные таймеры и echo после открытия personalFlightTime.zul
    pft_norm = pump_zk_timers(
        sess, dtid, pfx, pft_norm,
        referer_url=f"{MERIDIAN_BASE_URL}/personalFlightTime.zul",
        debug_log=debug_log,
        step_label="pft_init",
        default_timer_uuid=page_timer_uuid,
        force_default=True
    )

    # Если после первичного таймера список месяцев еще пуст — нажимаем кнопку "Обновить" (<PFX>a2)
    if 'Listitem' not in pft_norm:
        buttons = [w for w in init_widgets if 'Button' in w['type']]
        refresh_btn = next((w for w in buttons if 'Обновить' in w['props_raw'] or 'refresh.png' in w['props_raw']), None)
        refresh_btn_uuid = refresh_btn['uuid'] if refresh_btn else (f"{pfx}a2" if pfx else None)
        if refresh_btn_uuid:
            r_ref = sess.post(f"{MERIDIAN_BASE_URL}/zkau", data={
                'dtid': dtid,
                'cmd_0': 'onClick',
                'uuid_0': refresh_btn_uuid,
                'data_0': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
            }, headers=au_headers, timeout=20)
            if r_ref.ok:
                ref_norm = normalize_zk_text(r_ref.text)
                debug_log.append(f"pft click refresh({refresh_btn_uuid}): len={len(ref_norm)}, resp={ref_norm[:140]}")
                pumped_ref = pump_zk_timers(
                    sess, dtid, pfx, ref_norm,
                    referer_url=f"{MERIDIAN_BASE_URL}/personalFlightTime.zul",
                    debug_log=debug_log,
                    step_label="pft_ref",
                    default_timer_uuid=page_timer_uuid,
                    force_default=True
                )
                pft_norm += "\n" + pumped_ref

    widgets = find_zk_widgets(pft_norm)

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

    listboxes = [w for w in init_widgets if 'Listbox' in w['type']]
    months_listbox_uuid = listboxes[0]['uuid'] if listboxes else (f"{pfx}d2" if pfx else None)

    month_item_uuids = []
    seen_m_uuids = set()
    last_listitem_uuid = None
    last_listitem_sel = False
    for w in widgets:
        if 'Listitem' in w['type']:
            last_listitem_uuid = w['uuid']
            last_listitem_sel = ('_sel:true' in w['props_raw'].replace(' ', '') or 'selected:true' in w['props_raw'].replace(' ', ''))
        elif 'Label' in w['type'] and last_listitem_uuid:
            val_m = re.search(r"value\s*:\s*['\"]([^'\"]+)['\"]", w['props_raw'])
            if val_m:
                lbl_val = val_m.group(1).strip().lower()
                if lbl_val in target_month_labels and last_listitem_uuid not in seen_m_uuids:
                    seen_m_uuids.add(last_listitem_uuid)
                    month_item_uuids.append((lbl_val, last_listitem_uuid, last_listitem_sel))
                    last_listitem_uuid = None

    debug_log.append(f"pft target months={list(target_month_labels)}, matched_uuids={month_item_uuids}")

    all_rows = []
    initial_rows = parse_zk_pft_rows(pft_norm)
    for r in initial_rows:
        if r not in all_rows:
            all_rows.append(r)

    debug_log.append(f"pft initial rows after timer: {len(all_rows)}")

    if months_listbox_uuid:
        for m_lbl, item_uuid, is_already_sel in month_item_uuids:
            if is_already_sel and len(initial_rows) > 0:
                continue
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
                    sel_text = normalize_zk_text(r_sel.text)
                    sel_text = pump_zk_timers(
                        sess, dtid, pfx, sel_text,
                        referer_url=f"{MERIDIAN_BASE_URL}/personalFlightTime.zul",
                        debug_log=debug_log,
                        step_label=f"pft_sel({m_lbl})",
                        default_timer_uuid=page_timer_uuid,
                        force_default=False
                    )
                    m_rows = parse_zk_pft_rows(sel_text)
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
    return "Гибридный мост Flight Log v3.1.11 (Direct z-macro Click + 3-Arg echo2 + Pinned Diag) работает штатно!"


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
            sess = meridian_login_session(email_addr, password, debug_log=debug_log)

            if action == 'meridian_latest':
                html_reports, deadhead_dates = fetch_meridian_workplan_reports(
                    sess, latest_only=True, debug_log=debug_log, email_or_login=email_addr
                )
                if html_reports:
                    return jsonify({
                        "mode": "meridian_latest",
                        "source": "web_meridian",
                        "htmlReports": html_reports,
                        "deadheadDates": deadhead_dates,
                        "debugLog": debug_log
                    })
            elif action == 'meridian_range' and date_from_str and date_to_str:
                today_dt = datetime.now()
                cutoff_30d = (today_dt - timedelta(days=31)).strftime('%Y-%m-%d')

                html_reports = []
                deadhead_dates = []
                pft_rows = []

                if date_from_str >= cutoff_30d:
                    html_reports, deadhead_dates = fetch_meridian_workplan_reports(
                        sess, date_from_str=date_from_str, date_to_str=date_to_str,
                        latest_only=False, debug_log=debug_log, email_or_login=email_addr
                    )
                else:
                    pft_rows = fetch_meridian_personal_flight_time(
                        sess, date_from_str, date_to_str, debug_log=debug_log
                    )
                    if date_to_str >= cutoff_30d:
                        html_reports, deadhead_dates = fetch_meridian_workplan_reports(
                            sess, date_from_str=cutoff_30d, date_to_str=date_to_str,
                            latest_only=False, debug_log=debug_log, email_or_login=email_addr
                        )

                return jsonify({
                    "mode": "meridian_range",
                    "source": "web_meridian",
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
