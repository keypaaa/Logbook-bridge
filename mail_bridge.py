import os
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from exchangelib import Credentials, Account, Configuration, DELEGATE, FileAttachment

app = Flask(__name__)
CORS(app)  # Разрешает приложению обращаться к серверу

# Проверочная страница (чтобы проверить работу сервера в браузере)
@app.route('/', methods=['GET'])
def home():
    return "Почтовый мост для логбука работает штатно!"

@app.route('/fetch-latest-report', methods=['POST'])
def fetch_latest_report():
    data = request.json or {}
    email_addr = (data.get('email') or '').strip()
    password = data.get('password') or ''
    server = data.get('server', 'mail.uzairways.com')
    subject_filter = data.get('subject', 'Полетное задание')

    if not email_addr or not password:
        return jsonify({"error": "Не указан логин или пароль от почты."}), 400

    try:
        # Прямое подключение к Exchange без браузера и капчи
        creds = Credentials(username=email_addr, password=password)
        config = Configuration(server=server, credentials=creds)
        account = Account(
            primary_smtp_address=email_addr,
            config=config,
            autodiscover=False,
            access_type=DELEGATE
        )

        # Берем последние 30 писем из Входящих по убыванию даты
        recent_emails = account.inbox.all().order_by('-datetime_received')[:30]

        for item in recent_emails:
            subj = (item.subject or "").lower()
            if subject_filter.lower() in subj or "flight activities" in subj:
                for attachment in item.attachments:
                    if isinstance(attachment, FileAttachment) and attachment.name.lower().endswith('.pdf'):
                        pdf_b64 = base64.b64encode(attachment.content).decode('utf-8')
                        return jsonify({
                            "fileName": attachment.name,
                            "messageId": item.message_id or str(item.datetime_received),
                            "emailDate": item.datetime_received.strftime('%d.%m.%Y %H:%M'),
                            "pdfBase64": pdf_b64
                        })

        return jsonify({"error": "Письмо с PDF-отчетом не найдено среди последних 30 писем."}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
