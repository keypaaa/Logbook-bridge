import os
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from exchangelib import Credentials, Account, Configuration, DELEGATE, FileAttachment

app = Flask(__name__)
CORS(app)

MAX_PDF_SIZE_BYTES = 25 * 1024 * 1024  # Защита от слишком больших файлов (макс. 25 МБ)

def is_trusted_sender(item):
    """Проверяет, что письмо пришло с корпоративного домена @uzairways.com."""
    sender = getattr(item, 'sender', None)
    if not sender:
        return True
    sender_email = (getattr(sender, 'email_address', '') or '').strip().lower()
    if '@' in sender_email and not sender_email.endswith('@uzairways.com'):
        return False
    return True

def is_valid_pdf_attachment(attachment):
    """Проверяет расширение .pdf, размер и сигнатуру заголовка %PDF- внутри файла."""
    if not isinstance(attachment, FileAttachment):
        return False
    name = (attachment.name or '').lower()
    if not name.endswith('.pdf'):
        return False
    content = attachment.content
    if not content or len(content) > MAX_PDF_SIZE_BYTES:
        return False
    # Проверка магических байтов %PDF- в начале файла
    if b'%PDF-' not in content[:1024]:
        return False
    return True

@app.route('/', methods=['GET'])
def home():
    return "Почтовый мост для логбука (v2.6 с защитой домена и проверкой PDF) работает штатно!"

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
        return jsonify({"error": "Не указан логин или пароль от почты."}), 400

    try:
        creds = Credentials(username=email_addr, password=password)
        config = Configuration(server=server, credentials=creds)
        account = Account(
            primary_smtp_address=email_addr,
            config=config,
            autodiscover=False,
            access_type=DELEGATE
        )

        # Фильтруем на самом сервере Exchange только письма с вложениями
        try:
            base_qs = account.inbox.filter(has_attachments=True)
        except Exception:
            base_qs = account.inbox.all()

        # ШАГ 1 ДЛЯ ЗАГРУЗКИ ЗА ПЕРИОД / ГОД: Быстрый поиск писем от проверенного отправителя
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

                if date_from_str <= item_date_str <= date_to_str:
                    if not is_trusted_sender(item):
                        continue
                    subj = (getattr(item, 'subject', '') or '').lower().replace('ё', 'е')
                    if subject_filter in subj or 'полетное задание' in subj or 'flight activities' in subj:
                        items_list.append({
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

        # ШАГ 2 ДЛЯ ЗАГРУЗКИ ЗА ПЕРИОД / ГОД: Скачивание и проверка одного конкретного PDF-отчета
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

            for attachment in (getattr(target_item, 'attachments', None) or []):
                if is_valid_pdf_attachment(attachment):
                    pdf_b64 = base64.b64encode(attachment.content).decode('utf-8')
                    return jsonify({
                        "mode": "single",
                        "fileName": attachment.name,
                        "messageId": getattr(target_item, 'message_id', None) or str(dt_rec),
                        "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                        "emailTimestamp": email_ts,
                        "pdfBase64": pdf_b64
                    })

            return jsonify({"skip": True, "reason": "no_valid_pdf"})

        # Режим обратной совместимости
        if date_from_str and date_to_str:
            qs_range = base_qs.only(
                'subject', 'datetime_received', 'message_id', 'sender'
            ).order_by('-datetime_received')

            reports_list = []
            for item in qs_range[:500]:
                dt_rec = getattr(item, 'datetime_received', None)
                if not dt_rec:
                    continue
                local_dt = dt_rec + timedelta(hours=5)
                item_date_str = local_dt.strftime('%Y-%m-%d')
                if item_date_str < date_from_str:
                    break
                if date_from_str <= item_date_str <= date_to_str:
                    if not is_trusted_sender(item):
                        continue
                    subj = (getattr(item, 'subject', '') or '').lower().replace('ё', 'е')
                    if subject_filter in subj or 'полетное задание' in subj:
                        full_item = account.inbox.get(id=item.id)
                        for attachment in (getattr(full_item, 'attachments', None) or []):
                            if is_valid_pdf_attachment(attachment):
                                pdf_b64 = base64.b64encode(attachment.content).decode('utf-8')
                                reports_list.append({
                                    "fileName": attachment.name,
                                    "messageId": getattr(full_item, 'message_id', None) or str(dt_rec),
                                    "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                                    "emailTimestamp": int(dt_rec.timestamp() * 1000),
                                    "pdfBase64": pdf_b64
                                })

            if not reports_list:
                return jsonify({"error": f"За период с {date_from_str} по {date_to_str} писем с отчетами не найдено."}), 404

            reports_list.reverse()
            return jsonify({
                "mode": "range",
                "count": len(reports_list),
                "reports": reports_list
            })

        # Стандартный режим: скачиваем только самый свежий отчет от проверенного отправителя
        qs_latest = base_qs.only(
            'subject', 'datetime_received', 'message_id', 'sender'
        ).order_by('-datetime_received')

        for item in qs_latest[:50]:
            if not is_trusted_sender(item):
                continue
            subj = (getattr(item, 'subject', '') or '').lower().replace('ё', 'е')
            if subject_filter in subj or 'полетное задание' in subj or 'flight activities' in subj:
                full_item = account.inbox.get(id=item.id)
                for attachment in (getattr(full_item, 'attachments', None) or []):
                    if is_valid_pdf_attachment(attachment):
                        dt_rec = getattr(full_item, 'datetime_received', None)
                        local_dt = (dt_rec + timedelta(hours=5)) if dt_rec else datetime.now()
                        email_ts = int(dt_rec.timestamp() * 1000) if dt_rec else int(datetime.now().timestamp() * 1000)
                        pdf_b64 = base64.b64encode(attachment.content).decode('utf-8')
                        return jsonify({
                            "mode": "latest",
                            "fileName": attachment.name,
                            "messageId": getattr(full_item, 'message_id', None) or str(dt_rec),
                            "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                            "emailTimestamp": email_ts,
                            "pdfBase64": pdf_b64
                        })

        return jsonify({"error": "Письмо с PDF-отчетом от @uzairways.com не найдено среди последних 50 писем."}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
