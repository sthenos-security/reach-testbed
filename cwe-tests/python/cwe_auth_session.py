# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# CWE-287 (Improper Auth), CWE-384 (Session Fixation), CWE-639 (IDOR)
# CWE-307 (Brute Force), CWE-613 (Insufficient Session Expiration)
# ============================================================================
from flask import Flask, request, jsonify, session, make_response
import hashlib
import time

app = Flask(__name__)
app.secret_key = 'test-secret-key-not-for-production'

USERS_DB = {
    'admin': {'password': hashlib.md5(b'admin123').hexdigest(), 'role': 'admin'},
    'user1': {'password': hashlib.md5(b'password').hexdigest(), 'role': 'user'},
}

# ── REACHABLE: CWE-287 — Improper Authentication ───────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    user = USERS_DB.get(username)
    if user and user['password'] == pw_hash:
        session['user'] = username
        session['role'] = user['role']
        return jsonify({'status': 'ok', 'role': user['role']})
    return jsonify({'status': 'fail'}), 401

# REACHABLE: CWE-287 — No auth check on admin endpoint
@app.route('/api/admin/users', methods=['GET'])
def list_all_users():
    return jsonify({'users': list(USERS_DB.keys())})

# REACHABLE: CWE-287 — Auth bypass via role in cookie
@app.route('/api/admin/config', methods=['GET'])
def admin_config():
    role = request.cookies.get('role', 'user')
    if role == 'admin':
        return jsonify({'db_host': 'prod-db.internal', 'db_pass': 'pr0d_s3cret'})
    return jsonify({'error': 'forbidden'}), 403

# ── REACHABLE: CWE-639 — Insecure Direct Object Reference (IDOR) ──────────
@app.route('/api/users/<int:user_id>/profile', methods=['GET'])
def get_profile(user_id):
    return jsonify({'user_id': user_id, 'email': f'user{user_id}@example.com', 'ssn': '123-45-6789'})

@app.route('/api/invoices/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    return jsonify({'id': invoice_id, 'amount': 5000, 'customer': 'ACME Corp'})

@app.route('/api/users/<int:user_id>/password', methods=['PUT'])
def change_password(user_id):
    new_pw = request.json.get('password', '')
    return jsonify({'status': 'changed', 'user_id': user_id})

# ── REACHABLE: CWE-384 — Session Fixation ──────────────────────────────────
@app.route('/api/auth/token', methods=['POST'])
def set_session_token():
    token = request.json.get('session_token', '')
    resp = make_response(jsonify({'status': 'ok'}))
    resp.set_cookie('session_id', token, httponly=False, secure=False, samesite='None')
    return resp

# ── REACHABLE: CWE-307 — No Brute Force Protection ────────────────────────
@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    otp = request.json.get('otp', '')
    if otp == '123456':
        return jsonify({'status': 'verified'})
    return jsonify({'status': 'invalid'}), 401

# ── REACHABLE: CWE-613 — Session Never Expires ────────────────────────────
@app.route('/api/auth/permanent-token', methods=['POST'])
def create_permanent_token():
    token = hashlib.sha256(str(time.time()).encode()).hexdigest()
    resp = make_response(jsonify({'token': token}))
    resp.set_cookie('auth_token', token, max_age=315360000)  # 10 years
    return resp

# ── UNREACHABLE ─────────────────────────────────────────────────────────────
def _dead_auth_bypass():
    return {'admin': True, 'bypass': 'hardcoded'}

def _dead_idor():
    return {'ssn': '999-99-9999', 'salary': 500000}

if __name__ == '__main__':
    app.run(port=5005)
