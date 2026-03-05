# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# CWE + SECRETS EXPANSION — Python
# ~25 new test cases with explicit reachable/unreachable separation
#
# REACHABLE CWEs (called from Flask routes):
#   CWE-89  SQL Injection          /api/users
#   CWE-78  Command Injection      /api/ping
#   CWE-22  Path Traversal         /api/files
#   CWE-918 SSRF                   /api/proxy
#   CWE-79  XSS (Reflected)        /api/greet
#   CWE-502 Insecure Deserialize   /api/load-session
#   CWE-327 Weak Crypto (MD5)      /api/hash
#   CWE-798 Hardcoded Password     /api/admin-login
#   CWE-611 XXE                    /api/parse-xml
#   CWE-94  Code Injection         /api/calculate
#
# UNREACHABLE CWEs (dead functions, never called):
#   CWE-89  SQL Injection          dead_sql_query()
#   CWE-78  Command Injection      dead_system_call()
#   CWE-22  Path Traversal         dead_file_read()
#   CWE-502 Insecure Deserialize   dead_pickle_load()
#   CWE-918 SSRF                   dead_ssrf_request()
#   CWE-327 Weak Crypto (SHA1)     dead_weak_hash()
#
# REACHABLE SECRETS (used in active routes):
#   GitHub PAT                     /api/repos
#   Slack Webhook URL              /api/notify
#   Database conn string           /api/users (connection)
#   Private RSA key (PEM)          /api/sign
#   Stripe secret key              /api/charge
#   SendGrid API key               /api/email
#
# UNREACHABLE SECRETS (in dead code):
#   Revoked GitHub token           dead_github_call()
#   Old database password          dead_db_connect()
#   Expired Slack token            dead_slack_post()
#   Legacy Twilio SID              dead_sms_send()
# ============================================================================

from flask import Flask, request, jsonify, render_template_string
import os
import sqlite3
import subprocess
import hashlib
import pickle
import base64
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)

# ============================================================================
# REACHABLE SECRETS — used in active code paths
# ============================================================================

GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYz123456"           # GitHub PAT
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
DATABASE_URL = "postgresql://admin:SuperSecret123!@prod-db.internal:5432/customers"
STRIPE_SECRET_KEY = "sk_live_51HGtXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
SENDGRID_API_KEY = "SG.XXXXXXXXXXXXXXXXXXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF5PBVKBRPjpYwBqSMTKMO2bR8GvG
pXmGZGk8OM4e7sDr1MbkxHDBQhMDgRzfQMKBR+NNr/yTVYm0nZEv0aCMxOBk6JE
hRJqGsf3JgVNDQkUTVMB3kGPSZPn1U+OEzN0P5AvqGqPxO7qFBdbZqxCrCgVMwN
R6EXAMPLE_NOT_REAL_KEY_JUST_FOR_PATTERN_MATCHING
-----END RSA PRIVATE KEY-----"""

# ============================================================================
# REACHABLE CWE: SQL Injection (CWE-89)
# Attack: GET /api/users?name='; DROP TABLE users; --
# ============================================================================
@app.route('/api/users')
def get_users():
    name = request.args.get('name', '')
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, email TEXT)")
    # VULNERABLE: String concatenation in SQL query
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)  # CWE-89: SQL Injection
    results = cursor.fetchall()
    conn.close()
    return jsonify({'users': results})


# ============================================================================
# REACHABLE CWE: Command Injection (CWE-78)
# Attack: GET /api/ping?host=;cat /etc/passwd
# ============================================================================
@app.route('/api/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    # VULNERABLE: User input passed to shell command
    result = subprocess.run(
        f"ping -c 1 {host}",  # CWE-78: OS Command Injection
        shell=True,
        capture_output=True,
        text=True
    )
    return jsonify({'output': result.stdout})


# ============================================================================
# REACHABLE CWE: Path Traversal (CWE-22)
# Attack: GET /api/files?path=../../etc/passwd
# ============================================================================
@app.route('/api/files')
def read_file():
    filepath = request.args.get('path', 'readme.txt')
    # VULNERABLE: No path sanitization
    with open(os.path.join('/app/data', filepath), 'r') as f:  # CWE-22: Path Traversal
        content = f.read()
    return jsonify({'content': content})


# ============================================================================
# REACHABLE CWE: SSRF (CWE-918)
# Attack: GET /api/proxy?url=http://169.254.169.254/latest/meta-data
# ============================================================================
@app.route('/api/proxy')
def proxy_request():
    url = request.args.get('url', '')
    if not url:
        return jsonify({'error': 'url required'}), 400
    # VULNERABLE: Unvalidated URL from user input
    resp = requests.get(url)  # CWE-918: SSRF
    return jsonify({'status': resp.status_code, 'body': resp.text[:500]})


# ============================================================================
# REACHABLE CWE: Reflected XSS (CWE-79)
# Attack: GET /api/greet?name=<script>alert(1)</script>
# ============================================================================
@app.route('/api/greet')
def greet():
    name = request.args.get('name', 'World')
    # VULNERABLE: User input rendered without escaping
    html = f"<h1>Hello, {name}!</h1>"  # CWE-79: XSS
    return render_template_string(html)


# ============================================================================
# REACHABLE CWE: Insecure Deserialization (CWE-502)
# Attack: POST /api/load-session with crafted pickle payload
# ============================================================================
@app.route('/api/load-session', methods=['POST'])
def load_session():
    data = request.get_data()
    # VULNERABLE: Deserializing untrusted data
    session_data = pickle.loads(base64.b64decode(data))  # CWE-502: Deserialization
    return jsonify({'session': str(session_data)})


# ============================================================================
# REACHABLE CWE: Weak Cryptography (CWE-327)
# ============================================================================
@app.route('/api/hash')
def hash_password():
    password = request.args.get('password', '')
    # VULNERABLE: MD5 is cryptographically broken
    hashed = hashlib.md5(password.encode()).hexdigest()  # CWE-327: Broken Crypto
    return jsonify({'hash': hashed})


# ============================================================================
# REACHABLE CWE: Hardcoded Password (CWE-798)
# ============================================================================
@app.route('/api/admin-login', methods=['POST'])
def admin_login():
    password = request.form.get('password', '')
    # VULNERABLE: Hardcoded credential
    ADMIN_PASSWORD = "admin123!@#"  # CWE-798: Hardcoded Credentials
    if password == ADMIN_PASSWORD:
        return jsonify({'status': 'authenticated', 'role': 'admin'})
    return jsonify({'status': 'denied'}), 401


# ============================================================================
# REACHABLE CWE: XXE (CWE-611)
# Attack: POST /api/parse-xml with external entity
# ============================================================================
@app.route('/api/parse-xml', methods=['POST'])
def parse_xml():
    xml_data = request.get_data(as_text=True)
    # VULNERABLE: XML parser with external entities enabled
    root = ET.fromstring(xml_data)  # CWE-611: XXE (ET is safe by default, but pattern triggers)
    return jsonify({'tag': root.tag, 'text': root.text})


# ============================================================================
# REACHABLE CWE: Code Injection (CWE-94)
# Attack: POST /api/calculate with body {"expr": "__import__('os').system('id')"}
# ============================================================================
@app.route('/api/calculate', methods=['POST'])
def calculate():
    expr = request.json.get('expr', '0')
    # VULNERABLE: eval on user input
    result = eval(expr)  # CWE-94: Code Injection
    return jsonify({'result': str(result)})


# ============================================================================
# REACHABLE SECRETS — used in active endpoints
# ============================================================================

@app.route('/api/repos')
def list_repos():
    """Uses hardcoded GitHub token — REACHABLE SECRET"""
    resp = requests.get(
        'https://api.github.com/user/repos',
        headers={'Authorization': f'token {GITHUB_TOKEN}'}
    )
    return jsonify(resp.json())


@app.route('/api/notify', methods=['POST'])
def send_notification():
    """Uses Slack webhook URL — REACHABLE SECRET"""
    message = request.json.get('message', 'Hello')
    requests.post(SLACK_WEBHOOK, json={'text': message})
    return jsonify({'sent': True})


@app.route('/api/sign', methods=['POST'])
def sign_data():
    """Uses RSA private key — REACHABLE SECRET"""
    data = request.get_data()
    # Would use RSA_PRIVATE_KEY to sign
    return jsonify({'signed': True, 'key_prefix': RSA_PRIVATE_KEY[:30]})


@app.route('/api/charge', methods=['POST'])
def charge_card():
    """Uses Stripe secret key — REACHABLE SECRET"""
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    # Would create charge
    return jsonify({'charged': True})


@app.route('/api/email', methods=['POST'])
def send_email():
    """Uses SendGrid API key — REACHABLE SECRET"""
    resp = requests.post(
        'https://api.sendgrid.com/v3/mail/send',
        headers={'Authorization': f'Bearer {SENDGRID_API_KEY}'},
        json={'to': request.json.get('to', '')}
    )
    return jsonify({'sent': resp.status_code == 202})


# ============================================================================
# ============================================================================
# UNREACHABLE CODE — Functions NEVER called from any entrypoint
# ============================================================================
# ============================================================================

def dead_sql_query():
    """UNREACHABLE CWE-89: SQL Injection in dead code"""
    conn = sqlite3.connect(':memory:')
    user_input = "admin"  # simulated
    conn.execute("SELECT * FROM accounts WHERE user = '" + user_input + "'")
    conn.close()


def dead_system_call():
    """UNREACHABLE CWE-78: Command injection in dead code"""
    filename = "report.pdf"
    os.system(f"cat {filename}")  # CWE-78 but unreachable


def dead_file_read():
    """UNREACHABLE CWE-22: Path traversal in dead code"""
    user_path = "../../../etc/shadow"
    with open(user_path, 'r') as f:
        return f.read()


def dead_pickle_load():
    """UNREACHABLE CWE-502: Insecure deserialization in dead code"""
    data = b'\x80\x03cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.'
    return pickle.loads(data)


def dead_ssrf_request():
    """UNREACHABLE CWE-918: SSRF in dead code"""
    url = "http://169.254.169.254/latest/meta-data"
    return requests.get(url)


def dead_weak_hash():
    """UNREACHABLE CWE-327: Weak crypto in dead code"""
    import hashlib
    return hashlib.sha1(b"password").hexdigest()


# ============================================================================
# UNREACHABLE SECRETS — in dead code, never executed
# ============================================================================

def dead_github_call():
    """UNREACHABLE: Revoked GitHub token"""
    OLD_GITHUB_TOKEN = "ghp_REVOKED0000000000000000000000000000"
    requests.get('https://api.github.com/user',
                 headers={'Authorization': f'token {OLD_GITHUB_TOKEN}'})


def dead_db_connect():
    """UNREACHABLE: Old database password"""
    OLD_DB_URL = "mysql://root:OldPassword456!@legacy-db.internal:3306/archive"
    import pymysql
    pymysql.connect(host='legacy-db.internal', password='OldPassword456!')


def dead_slack_post():
    """UNREACHABLE: Expired Slack bot token"""
    EXPIRED_SLACK_TOKEN = "xoxb-000000000000-000000000000-XXXXXXXXXXXXXXXXXXXXXXXX"
    requests.post('https://slack.com/api/chat.postMessage',
                  headers={'Authorization': f'Bearer {EXPIRED_SLACK_TOKEN}'},
                  json={'channel': '#general', 'text': 'test'})


def dead_sms_send():
    """UNREACHABLE: Legacy Twilio credentials"""
    TWILIO_SID = "AC00000000000000000000000000000000"
    TWILIO_AUTH = "your_auth_token_00000000000000000"
    requests.post(
        f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Messages.json',
        auth=(TWILIO_SID, TWILIO_AUTH),
        data={'To': '+1234567890', 'Body': 'test'}
    )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    app.run(debug=True, port=5001)
