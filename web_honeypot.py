# Libraries
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request

# Logging Format
logging_format = logging.Formatter('%(asctime)s %(message)s')

# HTTP Logger
funnel_logger = logging.getLogger('HTTP Logger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('http_audits.log', maxBytes=2_000_000, backupCount=5, encoding='utf-8')
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)


# Baseline honeypot
def web_honeypot(input_username="admin", input_password="password"):

    app = Flask(__name__)

    @app.route('/')
    def index():
        return render_template('wp-admin.html')

    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr

        funnel_logger.info(
            f'Client with IP Address: {ip_address} entered\n'
            f'Username: {username}, Password: {password}'
        )

        if username == input_username and password == input_password:
            return 'DEEBOODAH!'
        else:
            return "Invalid username or password. Please Try Again."

    return app


def run_web_honeypot(host="0.0.0.0", port=5000, input_username="admin", input_password="password"):
    app = web_honeypot(input_username, input_password)
    # debug=False: honeypot phải luôn tắt debug mode, tránh lộ Werkzeug
    # interactive debugger (cho phép thực thi code từ xa) khi có exception.
    app.run(debug=False, port=port, host=host)