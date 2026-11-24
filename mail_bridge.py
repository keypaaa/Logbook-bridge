import os
import re
import json
import time
import hmac
import hashlib
import secrets
import base64
import xml.etree.ElementTree as ET
import urllib3
from datetime import datetime, timedelta
import requests
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from exchangelib import Credentials, Account, Configuration, DELEGATE, FileAttachment

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Настройки безопасности моста (Пункт 8):
# Разрешаем локальный запуск файла Logbook.html с телефона/ПК (Origin: null), localhost и доверенные хостинги,
# блокируя произвольные сторонние сайты от несанкционированных кросс-доменных запросов.
BRIDGE_SECRET = os.environ.get('BRIDGE_SECRET', '').strip()
VERIFY_MERIDIAN_SSL = os.environ.get('VERIFY_MERIDIAN_SSL', 'auto').strip().lower()
EXTRA_ALLOWED_ORIGINS = [
    o.strip().lower() for o in os.environ.get('ALLOWED_ORIGINS', '').split(',') if o.strip()
]

TRUSTED_ORIGIN_PATTERNS = [
    re.compile(r'^null$'),
    re.compile(r'^file://'),
    re.compile(r'^content://'),
    re.compile(r'^capacitor://'),
    re.compile(r'^ionic://'),
    re.compile(r'^https?://(localhost|127\.0\.0\.1)(:\d+)?$'),
    re.compile(r'^https://[a-z0-9\-]+\.onrender\.com$'),
    re.compile(r'^https://[a-z0-9\-]+\.github\.io$'),
    re.compile(r'^https://[a-z0-9\-]+\.netlify\.app$'),
    re.compile(r'^https://[a-z0-9\-]+\.vercel\.app$'),
    re.compile(r'^https://[a-z0-9\-]+\.pages\.dev$'),
]


def is_allowed_origin(origin_val: str) -> bool:
    if not origin_val:
        return True
    low = origin_val.strip().lower()
    if '*' in EXTRA_ALLOWED_ORIGINS or low in EXTRA_ALLOWED_ORIGINS:
        return True
    return any(rx.match(low) for rx in TRUSTED_ORIGIN_PATTERNS)


CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    allow_headers=["Content-Type", "X-Logbook-Client", "X-Logbook-Token"],
    methods=["GET", "POST", "OPTIONS"],
    max_age=86400
)

# Защита от перебора паролей (Rate Limiting по IP: не более 45 POST-запросов в минуту)
RATE_LIMIT_BUCKETS = {}
RATE_LIMIT_MAX_PER_MIN = int(os.environ.get('RATE_LIMIT_PER_MIN', '45'))

# Краткоживущий кэш сессий для бесшовного дочитывания больших периодов без таймаута 30 сек (Пункт 7)
MERIDIAN_STREAM_CACHE = {}
STREAM_TIME_BUDGET_SEC = 18.0


def check_rate_limit(ip_addr: str) -> bool:
    now = time.time()
    cutoff = now - 60.0
    if len(RATE_LIMIT_BUCKETS) > 500:
        stale_ips = [k for k, ts_list in RATE_LIMIT_BUCKETS.items() if not ts_list or ts_list[-1] < cutoff]
        for k in stale_ips:
            RATE_LIMIT_BUCKETS.pop(k, None)
    bucket = [t for t in RATE_LIMIT_BUCKETS.get(ip_addr, []) if t >= cutoff]
    if len(bucket) >= RATE_LIMIT_MAX_PER_MIN:
        RATE_LIMIT_BUCKETS[ip_addr] = bucket
        return False
    bucket.append(now)
    RATE_LIMIT_BUCKETS[ip_addr] = bucket
    return True


def prune_stream_cache():
    now = time.time()
    expired = [k for k, v in MERIDIAN_STREAM_CACHE.items() if now - v.get('created_at', 0) > 120.0]
    for k in expired:
        MERIDIAN_STREAM_CACHE.pop(k, None)


@app.before_request
def enforce_bridge_security():
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin', '')
        if origin and not is_allowed_origin(origin):
            return jsonify({"error": "Origin запрещён политикой безопасности моста."}), 403
        return None

    if request.path == '/fetch-latest-report' and request.method == 'POST':
        origin = request.headers.get('Origin', '')
        if origin and not is_allowed_origin(origin):
            return jsonify({"error": "Запрос со стороннего сайта заблокирован защитой CORS."}), 403

        client_ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or 'unknown').split(',')[0].strip()
        if not check_rate_limit(client_ip):
            return jsonify({"error": "Слишком много запросов. Подождите 1 минуту и попробуйте снова."}), 429

        if BRIDGE_SECRET:
            provided_token = (request.headers.get('X-Logbook-Token') or '').strip()
            if not provided_token or not hmac.compare_digest(provided_token, BRIDGE_SECRET):
                return jsonify({
                    "error": "Неверный секретный ключ моста (BRIDGE_SECRET). Укажите ключ в «Настройки сервера (Render)» внутри приложения."
                }), 401
    return None


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
# КЛИЕНТ WEB MERIDIAN (ZK 10.2.1 AU ПРОТОКОЛ + XML IFRAME ONLOAD)
# ==============================================================================

class ZkDesktopChannel:
    """Управляет монотонным заголовком ZK-SID в рамках одного dtid."""
    def __init__(self, sess, dtid, referer_url):
        self.sess = sess
        self.dtid = dtid
        self.referer_url = referer_url
        self.sid = 1

    def post(self, payload, timeout=25):
        data = dict(payload)
        data['dtid'] = self.dtid
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'Origin': 'https://faps.uzairways.com',
            'Referer': self.referer_url,
            'ZK-SID': str(self.sid)
        }
        self.sid += 1
        return self.sess.post(f"{MERIDIAN_BASE_URL}/zkau", data=data, headers=headers, timeout=timeout)


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
    """Извлекает виджеты ZK ['zul.Class','uuid',{props},...] с учетом вложенности скобок."""
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


def coerce_zk_js_to_json(raw_str):
    """Преобразует JS-литералы ZK вида {$u:'nVyT_2'} в валидный JSON для json.loads."""
    return re.sub(r"\{\s*\$u\s*:\s*['\"]([^'\"]+)['\"]\s*\}", r'{"$u":"\1"}', raw_str)


def extract_removed_uuids(zk_text):
    """Возвращает множество UUID виджетов, удаленных командой ['rm', ['uuid']]."""
    removed = set()
    for m in re.finditer(r"""['"]rm['"]\s*,\s*\[\s*['"]([a-zA-Z0-9_]+)['"]\s*\]""", zk_text or ""):
        removed.add(m.group(1))
    return removed


def extract_timers_and_echos(raw_text, pfx=None, default_timer_uuid=None, force_default=False, debug_log=None, include_repeating_timers=False):
    """
    Извлекает команды echo/echo2 (с точным 3-м аргументом) и одноразовые таймеры zul.utl.Timer.
    Возвращает (timers_list, echos_list), где элемент echos_list = (uuid, evt_name, has_data, data_val).
    """
    text = normalize_zk_text(raw_text)
    timers = []
    echos = []
    seen_echo_keys = set()

    stripped = raw_text.strip() if isinstance(raw_text, str) else ""
    if stripped.startswith('{') and '"rs"' in stripped:
        try:
            parsed_json = json.loads(coerce_zk_js_to_json(stripped))
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

    for src_txt in (raw_text if isinstance(raw_text, str) else "", text):
        for em in re.finditer(
            r"""['"]echo2?['"]\s*,\s*\[\s*(?:\{\s*['"]?\$u['"]?\s*:\s*)?['"]([a-zA-Z0-9_]+)['"]\s*\}?\s*,\s*['"]([^'"]+)['"](?:\s*,\s*([^\]]+))?\s*\]""",
            src_txt
        ):
            t_uuid, e_name, raw_third = em.group(1), em.group(2), em.group(3)
            has_d = False
            d_val = None
            if raw_third is not None and raw_third.strip() != "":
                has_d = True
                rt = raw_third.strip()
                try:
                    d_val = json.loads(rt)
                except Exception:
                    if re.match(r'^-?\d+$', rt):
                        d_val = int(rt)
                    else:
                        d_val = rt.strip("'\"")
            ekey = f"{t_uuid}:{e_name}:{json.dumps(d_val, ensure_ascii=False, sort_keys=True) if has_d else 'NO_DATA'}"
            if ekey not in seen_echo_keys:
                seen_echo_keys.add(ekey)
                echos.append((t_uuid, e_name, has_d, d_val))

    widgets = find_zk_widgets(text)
    for w in widgets:
        if 'Timer' in w['type']:
            u = w['uuid']
            props = w['props_raw'].replace(' ', '')
            if 'running:false' in props:
                continue
            if "id:'timer'" in props or 'id:"timer"' in props or 'delay:60000' in props or 'delay:30000' in props or 'delay:10000' in props:
                continue
            if not include_repeating_timers and 'repeats:true' in props:
                continue
            if u not in timers:
                timers.append(u)

    if force_default and default_timer_uuid and not echos and default_timer_uuid not in timers:
        timers.append(default_timer_uuid)

    if debug_log is not None:
        if echos:
            short_e = [(u, en, d if hd else 'no3rd') for (u, en, hd, d) in echos]
            debug_log.append(f"echos: {short_e}")
        if timers:
            debug_log.append(f"timers: {timers}")

    return timers, echos


def pump_zk_timers(zkc, pfx, raw_text, debug_log=None, step_label="pump", default_timer_uuid=None, force_default=False, include_repeating_timers=False):
    """
    Отправляет точные события ZK 10 echo (cmd_0=echo&opt_0=i&data_0={"":[evt, ...]})
    и одноразовые таймеры cmd_0=onTimer до получения таблиц или Iframe отчёта.
    """
    if debug_log is None:
        debug_log = []

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
                force_default=(force_default and pass_idx == 0),
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
            echo_arr = [evt_name, data_val] if has_data else [evt_name]
            r_echo = zkc.post({
                'cmd_0': 'echo',
                'opt_0': 'i',
                'uuid_0': target_u,
                'data_0': json.dumps({"": echo_arr}, ensure_ascii=False)
            }, timeout=30)
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

        if 'dynamic-html' in combined:
            break

        if not pending_echos and known_timers:
            for t_uuid in list(known_timers):
                for poll_idx in range(4):
                    r_pump = zkc.post({
                        'cmd_0': 'onTimer',
                        'opt_0': 'i',
                        'uuid_0': t_uuid
                    }, timeout=20)
                    raw_pump = r_pump.text if r_pump.ok else ""
                    pump_norm = normalize_zk_text(raw_pump)
                    debug_log.append(f"{step_label} onTimer({t_uuid})#{poll_idx}: len={len(pump_norm)}")
                    if len(pump_norm) > 22:
                        combined += "\n" + pump_norm
                        next_step_raws.append(raw_pump)
                        got_meaningful_data = True
                    if 'dynamic-html' in pump_norm or 'Listitem' in pump_norm or '"rs":[]' in raw_pump.replace(" ", ""):
                        if t_uuid in known_timers:
                            known_timers.remove(t_uuid)
                        break
                    time.sleep(0.3)

        if not got_meaningful_data:
            break
        current_inputs = next_step_raws

    return combined


def meridian_login_session(email_or_login, password, debug_log=None):
    """Авторизуется на login.zul и фиксирует сессию через welcome.zul."""
    if debug_log is None:
        debug_log = []

    base_login = email_or_login.split('@')[0].strip() if '@' in email_or_login else email_or_login.strip()
    title_login = ".".join([p.capitalize() for p in base_login.split('.')])
    candidates = []
    for c in [base_login, title_login, base_login.lower(), email_or_login.strip()]:
        if c and c not in candidates:
            candidates.append(c)

    last_err = "Не удалось подключиться к Web Meridian"
    prefer_tls_verify = (VERIFY_MERIDIAN_SSL not in ('false', '0', 'no', 'off'))
    strict_tls_verify = (VERIFY_MERIDIAN_SSL == 'strict')

    for login_candidate in candidates:
        sess = requests.Session()
        sess.verify = prefer_tls_verify
        sess.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
        })
        try:
            try:
                r = sess.get(f"{MERIDIAN_BASE_URL}/login.zul", timeout=18)
            except requests.exceptions.SSLError as ssl_err:
                if strict_tls_verify:
                    raise ssl_err
                # Корпоративный сервер может отдавать неполную цепочку промежуточных сертификатов на Linux
                sess.verify = False
                prefer_tls_verify = False
                debug_log.append("TLS: переключение на совместимый режим для корпоративного сертификата")
                r = sess.get(f"{MERIDIAN_BASE_URL}/login.zul", timeout=18)
            debug_log.append(f"GET login.zul: status={r.status_code}, len={len(r.text)}")
            if not r.ok:
                last_err = f"HTTP {r.status_code} при открытии login.zul"
                continue

            dtid, pfx = extract_zk_dtid_and_prefix(r.text)
            widgets = find_zk_widgets(r.text)
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

            zkc = ZkDesktopChannel(sess, dtid, r.url)
            r_au = zkc.post({
                'cmd_0': 'onChange',
                'uuid_0': login_uuid,
                'data_0': json.dumps({"value": login_candidate, "start": len(login_candidate)}),
                'cmd_1': 'onChange',
                'uuid_1': pass_uuid,
                'data_1': json.dumps({"value": password, "start": len(password)}),
                'cmd_2': 'onClick',
                'uuid_2': enter_uuid,
                'data_2': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
            }, timeout=18)
            au_norm = normalize_zk_text(r_au.text) if r_au.ok else ""
            debug_log.append(f"POST zkau login ({login_candidate}): status={r_au.status_code}, resp={au_norm[:140]}")

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


def extract_clean_xml_from_onload(raw_onload_text):
    """
    Вырезает блок <parameters><data>...</data></parameters> ДО декодирования 3,8 МБ вложений <files>
    и очищает JS-экранирование без искажения структуры XML.
    """
    if not raw_onload_text:
        return None
    start_idx = raw_onload_text.find('<parameters><data>')
    if start_idx == -1:
        start_idx = raw_onload_text.find('<parameters>')
    if start_idx == -1:
        return None

    end_idx = raw_onload_text.find(r'<\/data>', start_idx)
    end_len = 8
    if end_idx == -1:
        end_idx = raw_onload_text.find('</data>', start_idx)
        end_len = 7
    if end_idx == -1:
        return None

    sliced = raw_onload_text[start_idx:end_idx + end_len]
    unesc = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), sliced)
    unesc = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), unesc)
    unesc = (
        unesc
        .replace(r'\/', '/')
        .replace(r'\"', '"')
        .replace(r"\'", "'")
        .replace(r'\n', '\n')
        .replace(r'\r', '')
        .replace(r'\t', ' ')
        .replace('\\\\', '\\')
    )
    xml_doc = unesc + '</parameters>'
    xml_doc = re.sub(r'&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)', '&amp;', xml_doc)
    return xml_doc


def has_executed_legs_in_report(rep_text):
    if not rep_text:
        return False
    if '<parameters>' in rep_text:
        for m in re.finditer(r'<int\s+key="(?:totalTime|flighting)">(\d+)</int>', rep_text):
            if int(m.group(1)) > 0:
                return True
        return False
    for m in re.finditer(r'<[^>]*\bdata-key=["\'](?:totalTime|flighting)["\'][^>]*>', rep_text):
        for t_val in re.findall(r'\b(\d{2}:\d{2})\b', m.group(0)):
            if t_val != '00:00':
                return True
    return False


def extract_report_flight_date_any(rep_text):
    if not rep_text:
        return None, None
    if '<parameters>' in rep_text:
        for key_name in ('sectorDate', 'blockOffDate', 'starting', 'flightDate'):
            m = re.search(rf'<date\s+key="{key_name}">(\d{{4}})-(\d{{2}})-(\d{{2}})', rep_text)
            if m:
                yyyy, mm, dd = m.group(1), m.group(2), m.group(3)
                return f"{dd}.{mm}.{yyyy}", f"{yyyy}-{mm}-{dd}"
        return None, None
    m = re.search(r'data-key=["\']flightDate["\'][^>]*>\s*(\d{2})\.(\d{2})\.(\d{4})\s*<', rep_text)
    if m:
        dd, mm, yyyy = m.group(1), m.group(2), m.group(3)
        return f"{dd}.{mm}.{yyyy}", f"{yyyy}-{mm}-{dd}"
    return None, None


def is_pilot_deadhead_in_report_any(rep_text, email_or_login=""):
    if not email_or_login or not rep_text:
        return False
    local_part = email_or_login.split('@')[0].upper()
    tokens = [t for t in re.split(r'[._\-]+', local_part) if len(t) >= 3]
    if not tokens:
        return False

    if '<parameters>' in rep_text:
        try:
            root = ET.fromstring(rep_text)
            data_el = root.find('data')
            if data_el is None:
                return False
            in_cockpit = False
            in_dh = False
            in_aug = False
            for child in data_el:
                k = child.attrib.get('key', '')
                if k == 'flightCrew':
                    fc_txt = ET.tostring(child, encoding='unicode').upper()
                    in_cockpit = any(tok in fc_txt for tok in tokens)
                elif k in ('dhCrew', 'extraCrew'):
                    dh_txt = ET.tostring(child, encoding='unicode').upper()
                    if any(tok in dh_txt for tok in tokens):
                        in_dh = True
                elif k == 'flight':
                    for leg in child:
                        for sub in leg:
                            if sub.attrib.get('key') == 'augmentCrew':
                                aug_txt = ET.tostring(sub, encoding='unicode').upper()
                                if any(tok in aug_txt for tok in tokens):
                                    in_aug = True
            return bool(in_dh and not in_cockpit and not in_aug)
        except Exception:
            return False

    fc_m = re.search(r'data-key=["\']flightCrew["\']([\s\S]*?)(?:data-key=["\'](?:cabinCrew|extraCrew|otherCrew)["\']|FLIGHT\s+REPORT)', rep_text, re.I)
    ec_m = re.search(r'data-key=["\']extraCrew["\']([\s\S]*?)(?:data-key=["\']otherCrew["\']|MEDICAL\s+CHECK|FLIGHT\s+REPORT)', rep_text, re.I)
    fc_text = (fc_m.group(1) if fc_m else "").upper()
    ec_text = (ec_m.group(1) if ec_m else "").upper()
    in_cockpit = any(tok in fc_text for tok in tokens)
    in_dh = any(tok in ec_text for tok in tokens)
    return bool(in_dh and not in_cockpit)


def extract_wp_table_dates(zk_text):
    dates = []
    for dm in re.finditer(r"(?:value|label)\s*:\s*['\"](\d{2})\.(\d{2})\.(\d{4})\s*\(", zk_text):
        ymd = f"{dm.group(3)}-{dm.group(2)}-{dm.group(1)}"
        if ymd not in dates:
            dates.append(ymd)
    return dates


def extract_listbox_meta(zk_text, pfx=None):
    widgets = find_zk_widgets(zk_text)
    all_listboxes = [w for w in widgets if 'Listbox' in w['type']]
    wp_lb = next((w for w in all_listboxes if 'workplan-table' in w['props_raw'] or 'workPlanListbox' in w['props_raw']), None)
    if not wp_lb and all_listboxes:
        wp_lb = all_listboxes[0]
    lb_uuid = wp_lb['uuid'] if wp_lb else (f"{pfx}g2" if pfx else None)
    total_size = 50
    if wp_lb:
        tm = re.search(r"_totalSize\s*:\s*(\d+)", wp_lb['props_raw'])
        if tm:
            total_size = int(tm.group(1))
    return lb_uuid, total_size


def parse_workplan_rows_and_icons(zk_text, email_or_login="", debug_log=None):
    """
    Прямая привязка каждого живого макроса zk.Macro иконки Полетное задание к родительскому Listitem
    без сдвига индексов на строках сторонних перевозчиков и с отсевом удаленных (rm) виджетов.
    """
    removed_uuids = extract_removed_uuids(zk_text)
    widgets = find_zk_widgets(zk_text)
    deadhead_dates = []
    report_targets = []
    seen_macros = set()

    current_listitem_uuid = None
    current_row_index = None
    current_date_str = None
    current_date_ymd = None
    current_flight_no = ""

    for idx_w, w in enumerate(widgets):
        if 'Listitem' in w['type']:
            current_listitem_uuid = w['uuid']
            current_flight_no = ""
            im = re.search(r"_index\s*:\s*(\d+)", w['props_raw'])
            current_row_index = int(im.group(1)) if im else None
        elif 'Label' in w['type'] or 'Listcell' in w['type']:
            val_m = re.search(r"(?:value|label)\s*:\s*['\"]([^'\"]+)['\"]", w['props_raw'])
            if val_m:
                v = val_m.group(1).strip()
                dm = re.match(r"^(\d{2})\.(\d{2})\.(\d{4})\s*\(", v)
                if dm:
                    current_date_str = f"{dm.group(1)}.{dm.group(2)}.{dm.group(3)}"
                    current_date_ymd = f"{dm.group(3)}-{dm.group(2)}-{dm.group(1)}"
                elif re.match(r"^HY\s*\d+$", v):
                    current_flight_no = v.replace(" ", "")
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
            if 'полетное задание' in props_low or 'flighttask' in props_low or 'flight_task' in props_low:
                macro_w = None
                for back in range(1, 4):
                    if idx_w - back >= 0 and 'Macro' in widgets[idx_w - back]['type']:
                        macro_w = widgets[idx_w - back]
                        break
                target_macro_uuid = macro_w['uuid'] if macro_w else w['uuid']
                if target_macro_uuid in removed_uuids or w['uuid'] in removed_uuids:
                    continue
                if target_macro_uuid not in seen_macros:
                    seen_macros.add(target_macro_uuid)
                    report_targets.append({
                        'row_uuid': current_listitem_uuid,
                        'row_index': current_row_index,
                        'date_ymd': current_date_ymd,
                        'date_str': current_date_str,
                        'flight_no': current_flight_no,
                        'macro_uuid': target_macro_uuid,
                        'img_uuid': w['uuid']
                    })

    if debug_log is not None and report_targets:
        f0 = report_targets[0]
        debug_log.append(f"icon0: row={f0['row_uuid']}({f0['date_str']} {f0['flight_no']}), macro={f0['macro_uuid']}")

    return report_targets, deadhead_dates


def close_zk_modal_windows(zkc, zk_text):
    modal_wins = [w['uuid'] for w in find_zk_widgets(zk_text) if 'Window' in w['type'] and 'modal' in w['props_raw']]
    for mw_uuid in modal_wins:
        try:
            zkc.post({
                'cmd_0': 'onClose',
                'uuid_0': mw_uuid,
                'data_0': json.dumps({})
            }, timeout=10)
        except Exception:
            pass


def open_workplan_row_xml(zkc, sess, pfx, listbox_uuid, total_size, ft_btn_uuid, row_target, debug_log, idx_t=0):
    """
    Полный цикл открытия Полётного задания:
    1) onSelect строки + onClick первичного макроса -> echo(onSearchItemReportsEvent, 0)
    2) Извлечение живого пересозданного zk.Macro (с фильтрацией rm) и onClick -> echo(onLongRun_...)
    3) Прямой POST cmd_0=onLoad&uuid_0={iframe_uuid} -> получение чистого XML <parameters><data>
    4) Закрытие модального окна cmd_0=onClose
    """
    row_uuid = row_target.get('row_uuid')
    macro_uuid = row_target.get('macro_uuid')
    combined_modal = ""

    # ШАГ 1: Выделение строки и первичный клик по макросу (запускает onSearchItemReportsEvent)
    if listbox_uuid and row_uuid and macro_uuid:
        r_sel = zkc.post({
            'cmd_0': 'onSelect',
            'uuid_0': listbox_uuid,
            'data_0': json.dumps({
                "items": [row_uuid],
                "rodItemIndexRange": {"start": 0, "end": max(total_size - 1, 0)},
                "reference": row_uuid,
                "clearFirst": True,
                "selectAll": False,
                "pageX": 731, "pageY": 314, "which": 1, "x": 726, "y": 188
            }),
            'cmd_1': 'onClick',
            'uuid_1': macro_uuid,
            'data_1': json.dumps({"pageX": 731, "pageY": 314, "which": 1, "x": 8, "y": 13})
        }, timeout=20)
        raw_sel = r_sel.text if r_sel.ok else ""
        after_sel = pump_zk_timers(zkc, pfx, raw_sel, debug_log=debug_log, step_label=f"wp_sel#{idx_t}")
        combined_modal += "\n" + after_sel

    # ШАГ 2: Кликаем по свежему (не удаленному rm) макросу иконки отчета
    if 'zul.utl.Iframe' not in combined_modal:
        refreshed_targets, _ = parse_workplan_rows_and_icons(combined_modal)
        click_uuids = [rt['macro_uuid'] for rt in reversed(refreshed_targets) if rt.get('macro_uuid')]
        if not click_uuids and macro_uuid:
            click_uuids.append(macro_uuid)
        if ft_btn_uuid and ft_btn_uuid not in click_uuids:
            click_uuids.append(ft_btn_uuid)

        for c_uuid in click_uuids:
            r_clk = zkc.post({
                'cmd_0': 'onClick',
                'uuid_0': c_uuid,
                'data_0': json.dumps({"pageX": 732, "pageY": 310, "which": 1, "x": 9, "y": 9})
            }, timeout=20)
            raw_clk = r_clk.text if r_clk.ok else ""
            after_clk = pump_zk_timers(zkc, pfx, raw_clk, debug_log=debug_log, step_label=f"wp_open#{idx_t}")
            combined_modal += "\n" + after_clk
            if 'zul.utl.Iframe' in after_clk or 'dynamic-html' in after_clk:
                break

    # ШАГ 3: Находим UUID виджета zul.utl.Iframe и сразу вызываем cmd_0=onLoad (без скачивания HTML шаблона)
    modal_widgets = find_zk_widgets(combined_modal)
    iframe_w = next((w for w in modal_widgets if 'Iframe' in w['type']), None)
    iframe_uuid = iframe_w['uuid'] if iframe_w else None
    if not iframe_uuid:
        m_if = re.search(r"""['"]setAttr['"]\s*,\s*\[\s*\{\s*['"]?\$u['"]?\s*:\s*['"]([a-zA-Z0-9_]+)['"]\s*\}\s*,\s*['"]src['"]""", combined_modal)
        if m_if:
            iframe_uuid = m_if.group(1)

    report_payload = None
    if iframe_uuid:
        r_load = zkc.post({
            'cmd_0': 'onLoad',
            'uuid_0': iframe_uuid
        }, timeout=35)
        if r_load.ok:
            report_payload = extract_clean_xml_from_onload(r_load.text)
            debug_log.append(f"wp_onload#{idx_t}({iframe_uuid}): raw={len(r_load.text)}, xml={len(report_payload) if report_payload else 0}")

    # Резерв на случай статического HTML-отчета без XML setData
    if not report_payload:
        iframe_m = re.search(r"((?:/web\.meridian/)?reports/dynamic-html/[^'\"\s<>]+\.html[^'\"\s<>]*)", combined_modal)
        if iframe_m:
            rel_path = iframe_m.group(1)
            if not rel_path.startswith('/'):
                rel_path = '/web.meridian/' + rel_path
            r_html = sess.get("https://faps.uzairways.com" + rel_path, timeout=20)
            if r_html.ok and 'flightCrew' in r_html.text:
                report_payload = r_html.text

    close_zk_modal_windows(zkc, combined_modal)
    return report_payload


def shift_workplan_datebox(zkc, pfx, datebox_from_uuid, refresh_btn_uuid, target_start_dt, page_timer_uuid, debug_log):
    """Сдвигает начальную дату в Datebox с обязательным ключом z$dateKeys:['value'] и авто-откатом на +1 день."""
    for day_bump in (0, 1):
        cand_dt = target_start_dt + timedelta(days=day_bump)
        date_payload = {
            "value": f"{cand_dt.year}.{cand_dt.month}.{cand_dt.day}.12.0.0.0",
            "start": 10,
            "z$dateKeys": ["value"]
        }
        try:
            r_chg = zkc.post({
                'cmd_0': 'onChange',
                'uuid_0': datebox_from_uuid,
                'data_0': json.dumps(date_payload)
            }, timeout=15)
            if not r_chg.ok:
                continue

            r_ref = zkc.post({
                'cmd_0': 'onClick',
                'uuid_0': refresh_btn_uuid,
                'data_0': json.dumps({"pageX": 528, "pageY": 103, "which": 1, "x": 28, "y": 11})
            }, timeout=20)
            if not r_ref.ok:
                continue

            ref_norm = normalize_zk_text(r_ref.text)
            if 'showNotification' in ref_norm or 'интервале' in ref_norm or 'wrongValue' in ref_norm:
                debug_log.append(f"PIN:date_retry({cand_dt.strftime('%d.%m.%Y')}): {ref_norm[:140]}")
                continue

            pumped_ref = pump_zk_timers(
                zkc, pfx, r_ref.text,
                debug_log=debug_log,
                step_label="wp_ref",
                default_timer_uuid=page_timer_uuid
            )
            if 'Listitem' in pumped_ref:
                debug_log.append(f"PIN:date_ok({cand_dt.strftime('%d.%m.%Y')})")
                return pumped_ref
        except Exception as e:
            debug_log.append(f"PIN:date_exc: {e}")
    return None


def prepare_meridian_workplan_context(sess, date_from_str=None, date_to_str=None, latest_only=False, debug_log=None, email_or_login=""):
    if debug_log is None:
        debug_log = []

    r_wp = sess.get(f"{MERIDIAN_BASE_URL}/workplan.zul", timeout=20)
    if not r_wp.ok or 'login.zul' in r_wp.url:
        debug_log.append(f"GET workplan.zul failed: status={r_wp.status_code}, url={r_wp.url}")
        return None

    wp_initial_text = normalize_zk_text(r_wp.text)
    dtid, pfx = extract_zk_dtid_and_prefix(wp_initial_text)
    debug_log.append(f"wp init: dtid={dtid}, pfx={pfx}")
    if not dtid:
        return None

    zkc = ZkDesktopChannel(sess, dtid, f"{MERIDIAN_BASE_URL}/workplan.zul")
    page_timer_uuid = f"{pfx}02" if pfx else None

    # ШАГ 1: Загружаем стартовую таблицу Плана работ
    combined_wp_text = pump_zk_timers(
        zkc, pfx, r_wp.text,
        debug_log=debug_log,
        step_label="wp_init",
        default_timer_uuid=page_timer_uuid,
        force_default=False
    )

    init_dates = extract_wp_table_dates(combined_wp_text)
    now_uz = datetime.utcnow() + timedelta(hours=5)
    init_min_date = min(init_dates) if init_dates else now_uz.strftime('%Y-%m-%d')
    all_init_widgets = find_zk_widgets(combined_wp_text)

    dateboxes = [w for w in all_init_widgets if 'Datebox' in w['type']]
    datebox_from_uuid = dateboxes[0]['uuid'] if dateboxes else (f"{pfx}52" if pfx else None)

    buttons = [w for w in all_init_widgets if 'Button' in w['type'] or 'Toolbarbutton' in w['type']]
    refresh_btn = next((w for w in buttons if 'Обновить' in w['props_raw'] or 'refresh' in w['props_raw'].lower()), None)
    refresh_btn_uuid = refresh_btn['uuid'] if refresh_btn else (f"{pfx}92" if pfx else None)

    active_table_text = combined_wp_text
    earliest_allowed_dt = (now_uz - timedelta(days=30)).replace(hour=12, minute=0, second=0, microsecond=0)

    # ШАГ 2: Сдвиг Datebox (для периода или если в стартовом окне нет ни одной иконки отчета при latest_only)
    init_targets, _ = parse_workplan_rows_and_icons(active_table_text, email_or_login=email_or_login)
    need_date_shift = False
    target_start_dt = earliest_allowed_dt

    if not latest_only and datebox_from_uuid and refresh_btn_uuid:
        if date_from_str:
            try:
                req_dt = (datetime.strptime(date_from_str, '%Y-%m-%d') - timedelta(days=1)).replace(hour=12, minute=0, second=0, microsecond=0)
                if req_dt > target_start_dt:
                    target_start_dt = req_dt
            except Exception:
                pass
        if target_start_dt.strftime('%Y-%m-%d') < init_min_date:
            need_date_shift = True
    elif latest_only and not init_targets and datebox_from_uuid and refresh_btn_uuid:
        need_date_shift = True

    if need_date_shift:
        shifted_text = shift_workplan_datebox(
            zkc, pfx, datebox_from_uuid, refresh_btn_uuid,
            target_start_dt, page_timer_uuid, debug_log
        )
        if shifted_text:
            active_table_text = shifted_text

    listbox_uuid, total_size = extract_listbox_meta(active_table_text, pfx=pfx)

    # ШАГ 2.5: Догрузка строк ZK Render-On-Demand (если _totalSize > 50)
    if listbox_uuid and total_size > 50:
        cutoff_load_ymd = date_to_str if date_to_str else (now_uz + timedelta(days=1)).strftime('%Y-%m-%d')
        for offset in range(50, min(total_size, 250), 50):
            loaded_dates = extract_wp_table_dates(active_table_text)
            if loaded_dates and max(loaded_dates) > cutoff_load_ymd:
                break
            try:
                r_rod = zkc.post({
                    'cmd_0': 'onDataLoading',
                    'opt_0': 'i',
                    'uuid_0': listbox_uuid,
                    'data_0': json.dumps({"offset": offset, "limit": 50})
                }, timeout=20)
                if r_rod.ok and len(r_rod.text) > 30:
                    active_table_text += "\n" + normalize_zk_text(r_rod.text)
            except Exception:
                break

    icon_logs = []
    report_targets, deadhead_dates = parse_workplan_rows_and_icons(
        active_table_text, email_or_login=email_or_login, debug_log=icon_logs
    )
    for il in icon_logs:
        debug_log.append(f"PIN:{il}")

    active_dates = extract_wp_table_dates(active_table_text)
    debug_log.append(f"PIN:wp_tbl: dates={active_dates[:2]}..{active_dates[-1:]}, icons={len(report_targets)}, total={total_size}")

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
    elif min_ymd and max_ymd:
        report_targets = [
            t for t in report_targets
            if not t.get('date_ymd') or (min_ymd <= t['date_ymd'] <= max_ymd)
        ]

    ft_btn = next((w for w in buttons if 'Полетное задание' in w['props_raw'] or 'FT' in w['props_raw']), None)
    ft_btn_uuid = ft_btn['uuid'] if ft_btn else (f"{pfx}u2" if pfx else None)

    return {
        "zkc": zkc,
        "sess": sess,
        "pfx": pfx,
        "listbox_uuid": listbox_uuid,
        "total_size": total_size,
        "ft_btn_uuid": ft_btn_uuid,
        "targets": report_targets,
        "deadhead_dates": deadhead_dates,
        "min_ymd": min_ymd,
        "max_ymd": max_ymd
    }


def fetch_meridian_workplan_reports(sess, date_from_str=None, date_to_str=None, latest_only=False, debug_log=None, email_or_login=""):
    if debug_log is None:
        debug_log = []

    ctx = prepare_meridian_workplan_context(
        sess, date_from_str=date_from_str, date_to_str=date_to_str,
        latest_only=latest_only, debug_log=debug_log, email_or_login=email_or_login
    )
    if not ctx:
        return [], []

    zkc = ctx["zkc"]
    pfx = ctx["pfx"]
    listbox_uuid = ctx["listbox_uuid"]
    total_size = ctx["total_size"]
    ft_btn_uuid = ctx["ft_btn_uuid"]
    report_targets = ctx["targets"]
    deadhead_dates = ctx["deadhead_dates"]
    min_ymd = ctx["min_ymd"]
    max_ymd = ctx["max_ymd"]

    xml_reports = []
    for idx_t, target in enumerate(report_targets):
        try:
            rep_doc = open_workplan_row_xml(
                zkc, sess, pfx, listbox_uuid, total_size, ft_btn_uuid,
                row_target=target, debug_log=debug_log, idx_t=idx_t
            )
            if not rep_doc:
                debug_log.append(f"wp_row#{idx_t}: no xml")
                continue

            rep_d_str, rep_d_ymd = extract_report_flight_date_any(rep_doc)
            if is_pilot_deadhead_in_report_any(rep_doc, email_or_login):
                if rep_d_str and rep_d_str not in deadhead_dates:
                    deadhead_dates.append(rep_d_str)
                debug_log.append(f"wp_row#{idx_t} ({rep_d_str}): included D/H report")

            if not latest_only and min_ymd and max_ymd and rep_d_ymd:
                if not (min_ymd <= rep_d_ymd <= max_ymd):
                    continue

            if latest_only:
                if has_executed_legs_in_report(rep_doc):
                    xml_reports.append(rep_doc)
                    break
                else:
                    debug_log.append(f"wp_row#{idx_t} ({rep_d_str}): skipped 00:00")
                    continue
            else:
                if has_executed_legs_in_report(rep_doc) and rep_doc not in xml_reports:
                    xml_reports.append(rep_doc)
        except Exception as e:
            debug_log.append(f"wp_row err#{idx_t}: {e}")
            continue

    debug_log.append(f"workplan reports fetched: {len(xml_reports)}")
    return xml_reports, deadhead_dates


def parse_zk_pft_rows(raw_zk_text):
    """Извлекает строки правой таблицы рейсов из ответа personalFlightTime.zul."""
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


def prepare_meridian_pft_context(sess, date_from_str, date_to_str, debug_log=None):
    """Открывает personalFlightTime.zul, догружает глубокий список месяцев (при необходимости) и готовит очередь месяцев."""
    if debug_log is None:
        debug_log = []

    r_pft = sess.get(f"{MERIDIAN_BASE_URL}/personalFlightTime.zul", timeout=20)
    if not r_pft.ok or 'login.zul' in r_pft.url:
        debug_log.append(f"GET personalFlightTime.zul failed: {r_pft.status_code}, url={r_pft.url}")
        return None

    pft_norm = normalize_zk_text(r_pft.text)
    dtid, pfx = extract_zk_dtid_and_prefix(pft_norm)
    init_widgets = find_zk_widgets(pft_norm)
    if not dtid:
        return None

    zkc = ZkDesktopChannel(sess, dtid, f"{MERIDIAN_BASE_URL}/personalFlightTime.zul")
    page_timer_uuid = f"{pfx}02" if pfx else None

    pft_norm = pump_zk_timers(
        zkc, pfx, r_pft.text,
        debug_log=debug_log,
        step_label="pft_init",
        default_timer_uuid=page_timer_uuid,
        force_default=True
    )

    if 'Listitem' not in pft_norm:
        buttons = [w for w in init_widgets if 'Button' in w['type']]
        refresh_btn = next((w for w in buttons if 'Обновить' in w['props_raw'] or 'refresh.png' in w['props_raw']), None)
        refresh_btn_uuid = refresh_btn['uuid'] if refresh_btn else (f"{pfx}a2" if pfx else None)
        if refresh_btn_uuid:
            r_ref = zkc.post({
                'cmd_0': 'onClick',
                'uuid_0': refresh_btn_uuid,
                'data_0': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
            }, timeout=20)
            if r_ref.ok:
                pumped_ref = pump_zk_timers(
                    zkc, pfx, r_ref.text,
                    debug_log=debug_log,
                    step_label="pft_ref",
                    default_timer_uuid=page_timer_uuid,
                    force_default=True
                )
                pft_norm += "\n" + pumped_ref

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

    all_pft_widgets = find_zk_widgets(pft_norm)
    listboxes = [w for w in (init_widgets + all_pft_widgets) if 'Listbox' in w['type']]
    months_lb = listboxes[0] if listboxes else None
    months_listbox_uuid = months_lb['uuid'] if months_lb else (f"{pfx}d2" if pfx else None)

    # Если левый список месяцев длинный (>20-50 записей за прошлые годы) — догружаем через Render-On-Demand
    if months_listbox_uuid and months_lb:
        tm = re.search(r"_totalSize\s*:\s*(\d+)", months_lb['props_raw'])
        m_total = int(tm.group(1)) if tm else 0
        if m_total > 25:
            for offset in range(25, min(m_total, 120), 25):
                try:
                    r_rod = zkc.post({
                        'cmd_0': 'onDataLoading',
                        'opt_0': 'i',
                        'uuid_0': months_listbox_uuid,
                        'data_0': json.dumps({"offset": offset, "limit": 25})
                    }, timeout=15)
                    if r_rod.ok and len(r_rod.text) > 25:
                        pft_norm += "\n" + normalize_zk_text(r_rod.text)
                except Exception:
                    break

    widgets = find_zk_widgets(pft_norm)
    initial_rows = parse_zk_pft_rows(pft_norm)

    pending_months = []
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
                    if not (last_listitem_sel and len(initial_rows) > 0):
                        pending_months.append((lbl_val, last_listitem_uuid))
                    last_listitem_uuid = None

    return {
        "sess": sess,
        "zkc": zkc,
        "pfx": pfx,
        "page_timer_uuid": page_timer_uuid,
        "months_listbox_uuid": months_listbox_uuid,
        "initial_rows": initial_rows,
        "pending_months": pending_months
    }


def fetch_single_pft_month_rows(pft_ctx, m_lbl, item_uuid, debug_log=None):
    if debug_log is None:
        debug_log = []
    months_listbox_uuid = pft_ctx.get("months_listbox_uuid")
    if not months_listbox_uuid:
        return []
    zkc = pft_ctx["zkc"]
    pfx = pft_ctx["pfx"]
    page_timer_uuid = pft_ctx["page_timer_uuid"]
    r_sel = zkc.post({
        'cmd_0': 'onSelect',
        'uuid_0': months_listbox_uuid,
        'data_0': json.dumps({
            "items": [item_uuid],
            "reference": item_uuid,
            "clearFirst": True,
            "selectAll": False,
            "pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15
        }),
        'cmd_1': 'onClick',
        'uuid_1': item_uuid,
        'data_1': json.dumps({"pageX": 15, "pageY": 15, "which": 1, "x": 15, "y": 15})
    }, timeout=20)
    if not r_sel.ok:
        return []
    sel_text = pump_zk_timers(
        zkc, pfx, r_sel.text,
        debug_log=debug_log,
        step_label=f"pft_sel({m_lbl})",
        default_timer_uuid=page_timer_uuid
    )
    return parse_zk_pft_rows(sel_text)


def fetch_meridian_personal_flight_time(sess, date_from_str, date_to_str, debug_log=None):
    """Синхронная обёртка чтения Персонального налёта (для обратной совместимости)."""
    if debug_log is None:
        debug_log = []
    pft_ctx = prepare_meridian_pft_context(sess, date_from_str, date_to_str, debug_log=debug_log)
    if not pft_ctx:
        return []
    all_rows = []
    for r in pft_ctx["initial_rows"]:
        if r not in all_rows:
            all_rows.append(r)
    for m_lbl, item_uuid in pft_ctx["pending_months"]:
        try:
            m_rows = fetch_single_pft_month_rows(pft_ctx, m_lbl, item_uuid, debug_log=debug_log)
            for row in m_rows:
                if row not in all_rows:
                    all_rows.append(row)
        except Exception as e:
            debug_log.append(f"pft month err ({m_lbl}): {e}")
    debug_log.append(f"pft total rows: {len(all_rows)}")
    return all_rows


def save_stream_checkpoint(tok, email_hash, payload):
    MERIDIAN_STREAM_CACHE[tok] = {
        "email_hash": email_hash,
        "created_at": time.time(),
        **payload
    }
    if len(MERIDIAN_STREAM_CACHE) > 20:
        oldest_k = min(MERIDIAN_STREAM_CACHE, key=lambda k: MERIDIAN_STREAM_CACHE[k]["created_at"])
        if oldest_k != tok:
            MERIDIAN_STREAM_CACHE.pop(oldest_k, None)


def generate_meridian_range_stream(
    email_addr, password, date_from_str, date_to_str,
    start_index=0, resume_token="", pft_start_index=0, stream_phase=""
):
    """
    Потоковая NDJSON-выдача рейсов за период с помесячным стримингом Персонального налёта,
    построчным стримингом Плана работ и защитой 18 сек от 30-секундного таймаута Render/Gunicorn.
    """
    req_start = time.time()
    debug_log = []
    prune_stream_cache()
    email_hash = hashlib.sha256(email_addr.lower().encode('utf-8')).hexdigest()

    now_uz = datetime.utcnow() + timedelta(hours=5)
    cutoff_30d = (now_uz - timedelta(days=30)).strftime('%Y-%m-%d')
    needs_bg_mail = bool(date_from_str < cutoff_30d)

    def pack(obj):
        return json.dumps(obj, ensure_ascii=False) + "\n"

    try:
        sess = None
        pft_ctx = None
        ctx = None
        phase = stream_phase or ""

        if resume_token:
            cached = MERIDIAN_STREAM_CACHE.get(resume_token)
            if cached and cached.get("email_hash") == email_hash:
                sess = cached.get("sess")
                pft_ctx = cached.get("pft_ctx")
                ctx = cached.get("ctx")
                if not phase:
                    phase = cached.get("phase") or ("wp" if ctx else "")
                debug_log.append(f"stream resume phase={phase} wp#{start_index} pft#{pft_start_index}")

        if sess is None and ctx is None and pft_ctx is None:
            yield pack({"type": "status", "message": "Авторизация в Web Meridian..."})
            sess = meridian_login_session(email_addr, password, debug_log=debug_log)
            phase = "pft" if (start_index == 0 and date_from_str < cutoff_30d) else "wp_init"

        # ФАЗА 1: Помесячное потоковое чтение «Персонального налёта» (с защитой 18 сек даже на 12–24 месяцах)
        if phase == "pft":
            if pft_ctx is None:
                yield pack({"type": "status", "message": "Открытие таблицы Персонального налёта..."})
                pft_ctx = prepare_meridian_pft_context(sess, date_from_str, date_to_str, debug_log=debug_log)
                if pft_ctx and pft_ctx["initial_rows"]:
                    yield pack({
                        "type": "pft",
                        "pftRows": pft_ctx["initial_rows"],
                        "count": len(pft_ctx["initial_rows"])
                    })

            if pft_ctx:
                pending_months = pft_ctx["pending_months"]
                total_m = len(pending_months)
                for idx_m in range(pft_start_index, total_m):
                    if idx_m > pft_start_index and (time.time() - req_start) >= STREAM_TIME_BUDGET_SEC:
                        tok = resume_token or secrets.token_urlsafe(18)
                        save_stream_checkpoint(tok, email_hash, {
                            "phase": "pft",
                            "sess": pft_ctx["sess"],
                            "pft_ctx": pft_ctx
                        })
                        yield pack({
                            "type": "continue",
                            "phase": "pft",
                            "pftNextIndex": idx_m,
                            "nextIndex": 0,
                            "total": total_m,
                            "resumeToken": tok
                        })
                        return

                    m_lbl, item_uuid = pending_months[idx_m]
                    yield pack({
                        "type": "pft_progress",
                        "current": idx_m + 1,
                        "total": total_m,
                        "monthLabel": m_lbl
                    })
                    try:
                        m_rows = fetch_single_pft_month_rows(pft_ctx, m_lbl, item_uuid, debug_log=debug_log)
                        if m_rows:
                            yield pack({
                                "type": "pft",
                                "pftRows": m_rows,
                                "count": len(m_rows)
                            })
                    except Exception as m_err:
                        debug_log.append(f"pft month err ({m_lbl}): {m_err}")

            if date_to_str < cutoff_30d:
                if resume_token:
                    MERIDIAN_STREAM_CACHE.pop(resume_token, None)
                yield pack({
                    "type": "done",
                    "totalWp": 0,
                    "deadheadDates": [],
                    "debugLog": debug_log,
                    "needsBackgroundMailSync": needs_bg_mail
                })
                return

            # Если чтение многих месяцев PFT уже заняло >= 11 сек, обновляем чекпоинт перед открытием workplan.zul
            if (time.time() - req_start) >= 11.0:
                tok = resume_token or secrets.token_urlsafe(18)
                save_stream_checkpoint(tok, email_hash, {
                    "phase": "wp_init",
                    "sess": sess
                })
                yield pack({
                    "type": "continue",
                    "phase": "wp_init",
                    "nextIndex": 0,
                    "total": 1,
                    "resumeToken": tok
                })
                return
            phase = "wp_init"

        # ФАЗА 2: Инициализация таблицы «Плана работ» за последние 30 дней
        if phase == "wp_init" or (ctx is None and date_to_str >= cutoff_30d):
            if sess is None:
                sess = meridian_login_session(email_addr, password, debug_log=debug_log)
            wp_from = cutoff_30d if date_from_str < cutoff_30d else date_from_str
            yield pack({"type": "status", "message": "Поиск отчётов в Плане работ..."})
            ctx = prepare_meridian_workplan_context(
                sess, date_from_str=wp_from, date_to_str=date_to_str,
                latest_only=False, debug_log=debug_log, email_or_login=email_addr
            )
            start_index = 0

        if not ctx:
            if resume_token:
                MERIDIAN_STREAM_CACHE.pop(resume_token, None)
            yield pack({
                "type": "done",
                "totalWp": 0,
                "deadheadDates": [],
                "debugLog": debug_log,
                "needsBackgroundMailSync": needs_bg_mail
            })
            return

        targets = ctx["targets"]
        deadhead_dates = ctx["deadhead_dates"]
        min_ymd = ctx["min_ymd"]
        max_ymd = ctx["max_ymd"]
        total_targets = len(targets)

        if start_index == 0:
            yield pack({
                "type": "wp_plan",
                "total": total_targets,
                "deadheadDates": list(deadhead_dates)
            })

        seen_xmls = set()
        for idx_t in range(start_index, total_targets):
            if idx_t > start_index and (time.time() - req_start) >= STREAM_TIME_BUDGET_SEC:
                tok = resume_token or secrets.token_urlsafe(18)
                save_stream_checkpoint(tok, email_hash, {
                    "phase": "wp",
                    "sess": ctx["sess"],
                    "ctx": ctx
                })
                yield pack({
                    "type": "continue",
                    "phase": "wp",
                    "nextIndex": idx_t,
                    "total": total_targets,
                    "resumeToken": tok,
                    "deadheadDates": list(deadhead_dates)
                })
                return

            target = targets[idx_t]
            yield pack({
                "type": "progress",
                "current": idx_t + 1,
                "total": total_targets,
                "date": target.get("date_str") or "",
                "flightNo": target.get("flight_no") or ""
            })

            try:
                rep_doc = open_workplan_row_xml(
                    ctx["zkc"], ctx["sess"], ctx["pfx"],
                    ctx["listbox_uuid"], ctx["total_size"], ctx["ft_btn_uuid"],
                    row_target=target, debug_log=debug_log, idx_t=idx_t
                )
                if not rep_doc:
                    debug_log.append(f"wp_row#{idx_t}: no xml")
                    continue

                rep_d_str, rep_d_ymd = extract_report_flight_date_any(rep_doc)
                if is_pilot_deadhead_in_report_any(rep_doc, email_addr):
                    if rep_d_str and rep_d_str not in deadhead_dates:
                        deadhead_dates.append(rep_d_str)
                    debug_log.append(f"wp_row#{idx_t} ({rep_d_str}): included D/H report")

                if min_ymd and max_ymd and rep_d_ymd and not (min_ymd <= rep_d_ymd <= max_ymd):
                    continue

                if has_executed_legs_in_report(rep_doc) and rep_doc not in seen_xmls:
                    seen_xmls.add(rep_doc)
                    yield pack({
                        "type": "report",
                        "xml": rep_doc,
                        "index": idx_t,
                        "deadheadDates": list(deadhead_dates)
                    })
            except Exception as row_err:
                debug_log.append(f"wp_row err#{idx_t}: {row_err}")
                continue

        if resume_token:
            MERIDIAN_STREAM_CACHE.pop(resume_token, None)

        yield pack({
            "type": "done",
            "totalWp": total_targets,
            "deadheadDates": list(deadhead_dates),
            "debugLog": debug_log,
            "needsBackgroundMailSync": needs_bg_mail
        })
    except Exception as err:
        if resume_token:
            MERIDIAN_STREAM_CACHE.pop(resume_token, None)
        yield pack({
            "type": "error",
            "meridianError": str(err),
            "debugLog": debug_log,
            "needsBackgroundMailSync": needs_bg_mail
        })


@app.route('/', methods=['GET'])
def home():
    return "Гибридный мост Flight Log v3.1.22 (Exact PFT Block + D/H Synth + Payslip 12m) работает штатно!"


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
    use_stream = bool(data.get('stream'))
    start_index = int(data.get('startIndex') or 0)
    pft_start_index = int(data.get('pftStartIndex') or 0)
    stream_phase = (data.get('streamPhase') or '').strip()
    resume_token = (data.get('resumeToken') or '').strip()

    if not email_addr or not password:
        return jsonify({"error": "Не указан логин или пароль."}), 400

    # Потоковый режим загрузки за период с живым прогрессом и защитой от таймаута 30 сек (Пункт 7)
    if action == 'meridian_range' and use_stream and date_from_str and date_to_str:
        return Response(
            stream_with_context(
                generate_meridian_range_stream(
                    email_addr=email_addr,
                    password=password,
                    date_from_str=date_from_str,
                    date_to_str=date_to_str,
                    start_index=start_index,
                    resume_token=resume_token,
                    pft_start_index=pft_start_index,
                    stream_phase=stream_phase
                )
            ),
            mimetype='application/x-ndjson',
            headers={
                'Cache-Control': 'no-cache, no-transform',
                'X-Accel-Buffering': 'no'
            }
        )

    # ==========================================================================
    # РЕЖИМ 1: ЗАГРУЗКА С САЙТА WEB MERIDIAN (КРАЙНИЙ РЕЙС ИЛИ ЗА ПЕРИОД)
    # ==========================================================================
    if action in ('meridian_latest', 'meridian_range'):
        debug_log = []
        try:
            sess = meridian_login_session(email_addr, password, debug_log=debug_log)

            if action == 'meridian_latest':
                xml_reports, deadhead_dates = fetch_meridian_workplan_reports(
                    sess, latest_only=True, debug_log=debug_log, email_or_login=email_addr
                )
                if xml_reports:
                    return jsonify({
                        "mode": "meridian_latest",
                        "source": "web_meridian",
                        "htmlReports": xml_reports,
                        "xmlReports": xml_reports,
                        "deadheadDates": deadhead_dates,
                        "debugLog": debug_log
                    })
            elif action == 'meridian_range' and date_from_str and date_to_str:
                now_uz = datetime.utcnow() + timedelta(hours=5)
                cutoff_30d = (now_uz - timedelta(days=30)).strftime('%Y-%m-%d')

                xml_reports = []
                deadhead_dates = []
                pft_rows = []

                if date_from_str >= cutoff_30d:
                    xml_reports, deadhead_dates = fetch_meridian_workplan_reports(
                        sess, date_from_str=date_from_str, date_to_str=date_to_str,
                        latest_only=False, debug_log=debug_log, email_or_login=email_addr
                    )
                else:
                    pft_rows = fetch_meridian_personal_flight_time(
                        sess, date_from_str, date_to_str, debug_log=debug_log
                    )
                    if date_to_str >= cutoff_30d:
                        xml_reports, deadhead_dates = fetch_meridian_workplan_reports(
                            sess, date_from_str=cutoff_30d, date_to_str=date_to_str,
                            latest_only=False, debug_log=debug_log, email_or_login=email_addr
                        )

                return jsonify({
                    "mode": "meridian_range",
                    "source": "web_meridian",
                    "htmlReports": xml_reports,
                    "xmlReports": xml_reports,
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
                    "xmlReports": [],
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

        only_payslips = bool(data.get('onlyPayslips'))

        if action == 'list' and date_from_str and date_to_str:
            qs = base_qs.only(
                'subject', 'datetime_received', 'message_id', 'sender'
            ).order_by('-datetime_received')

            items_list = []
            for item in qs[:6000]:
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

                if not only_payslips and date_from_str <= item_date_str <= date_to_str:
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
