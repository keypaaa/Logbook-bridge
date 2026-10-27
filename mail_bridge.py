import os
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from exchangelib import Credentials, Account, Configuration, DELEGATE, FileAttachment

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def home():
    return "Почтовый мост для логбука (v2.3 точный период + автообновление легов) работает штатно!"

@app.route('/fetch-latest-report', methods=['POST'])
def fetch_latest_report():
    data = request.json or {}
    email_addr = (data.get('email') or '').strip()
    password = data.get('password') or ''
    server = data.get('server', 'mail.uzairways.com')
    subject_filter = (data.get('subject') or 'Полетное задание').lower().replace('ё', 'е')
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

        # Загружаем только нужные поля писем для быстрой работы без зависаний
        qs = account.inbox.all().only(
            'subject', 'datetime_received', 'message_id', 'attachments'
        ).order_by('-datetime_received')

        # Режим 1: Выбран диапазон дат (строго по дате получения письма в Ташкентском времени UTC+5)
        if date_from_str and date_to_str:
            reports_list = []

            for item in qs[:250]:
                if not getattr(item, 'datetime_received', None):
                    continue

                local_dt = item.datetime_received + timedelta(hours=5)
                item_date_str = local_dt.strftime('%Y-%m-%d')

                # Письма идут от новых к старым: как только дошли до писем раньше начальной даты — останавливаемся
                if item_date_str < date_from_str:
                    break

                if date_from_str <= item_date_str <= date_to_str:
                    subj = (getattr(item, 'subject', '') or '').lower().replace('ё', 'е')
                    if subject_filter in subj or 'flight activities' in subj or 'полетное задание' in subj:
                        for attachment in (getattr(item, 'attachments', None) or []):
                            if isinstance(attachment, FileAttachment) and (attachment.name or '').lower().endswith('.pdf'):
                                pdf_b64 = base64.b64encode(attachment.content).decode('utf-8')
                                reports_list.append({
                                    "fileName": attachment.name,
                                    "messageId": getattr(item, 'message_id', None) or str(item.datetime_received),
                                    "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                                    "emailTimestamp": int(item.datetime_received.timestamp() * 1000),
                                    "pdfBase64": pdf_b64
                                })

            if not reports_list:
                return jsonify({"error": f"За период с {date_from_str} по {date_to_str} писем с отчетами не найдено."}), 404

            # Разворачиваем список от старых к новым, чтобы более свежие исправленные письма шли после старых и обновляли их
            reports_list.reverse()
            return jsonify({
                "mode": "range",
                "count": len(reports_list),
                "reports": reports_list
            })

        # Режим 2: Скачиваем только самый свежий отчет
        for item in qs[:30]:
            subj = (getattr(item, 'subject', '') or '').lower().replace('ё', 'е')
            if subject_filter in subj or 'flight activities' in subj or 'полетное задание' in subj:
                for attachment in (getattr(item, 'attachments', None) or []):
                    if isinstance(attachment, FileAttachment) and (attachment.name or '').lower().endswith('.pdf'):
                        local_dt = item.datetime_received + timedelta(hours=5) if getattr(item, 'datetime_received', None) else datetime.now()
                        email_ts = int(item.datetime_received.timestamp() * 1000) if getattr(item, 'datetime_received', None) else int(datetime.now().timestamp() * 1000)
                        pdf_b64 = base64.b64encode(attachment.content).decode('utf-8')
                        return jsonify({
                            "mode": "latest",
                            "fileName": attachment.name,
                            "messageId": getattr(item, 'message_id', None) or str(item.datetime_received),
                            "emailDate": local_dt.strftime('%d.%m.%Y %H:%M'),
                            "emailTimestamp": email_ts,
                            "pdfBase64": pdf_b64
                        })

        return jsonify({"error": "Письмо с PDF-отчетом не найдено среди последних 30 писем."}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
