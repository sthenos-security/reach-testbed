# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# CWE-200 (Info Exposure), CWE-209 (Error Info Leak), CWE-532 (Log Injection)
# CWE-117 (Log Injection), CWE-614 (Insecure Cookie)
# ============================================================================
from flask import Flask, request, jsonify, make_response
import logging
import traceback
import sys

app = Flask(__name__)
logger = logging.getLogger(__name__)

# ============================================================================
# REACHABLE: CWE-200 — Information Exposure
# ============================================================================
@app.route('/api/debug/env', methods=['GET'])
def expose_env():
    """Exposes all environment variables — leaks secrets."""
    import os
    return jsonify(dict(os.environ))

@app.route('/api/debug/config', methods=['GET'])
def expose_config():
    """Exposes Flask config including SECRET_KEY."""
    return jsonify({k: str(v) for k, v in app.config.items()})

# ============================================================================
# REACHABLE: CWE-209 — Error Message Info Leak
# ============================================================================
@app.route('/api/users/<int:uid>', methods=['GET'])
def get_user(uid):
    try:
        conn = None  # Would be DB connection
        raise Exception(f"Connection to db://admin:password@prod-db:5432/users failed for uid={uid}")
    except Exception as e:
        # BAD: Full exception + stack trace to client
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc(),
            'python_version': sys.version,
        }), 500

@app.route('/api/query', methods=['POST'])
def run_query():
    query = request.json.get('q', '')
    try:
        raise Exception(f"SQL error near '{query}': table users columns (id, name, ssn, salary)")
    except Exception as e:
        # BAD: Leaks schema info in error
        return jsonify({'error': str(e), 'query': query}), 500

# ============================================================================
# REACHABLE: CWE-532 — Sensitive Info in Logs
# ============================================================================
@app.route('/api/auth/login', methods=['POST'])
def login():
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    token = request.headers.get('Authorization', '')
    # BAD: Logging credentials
    logger.info(f"Login attempt: user={username} password={password} token={token}")
    return jsonify({'status': 'ok'})

@app.route('/api/payment/process', methods=['POST'])
def process_payment():
    card_number = request.json.get('card', '')
    cvv = request.json.get('cvv', '')
    # BAD: Logging PCI data
    logger.info(f"Payment: card={card_number} cvv={cvv}")
    return jsonify({'status': 'processed'})

# ============================================================================
# REACHABLE: CWE-117 — Log Injection
# ============================================================================
@app.route('/api/audit/log', methods=['POST'])
def audit_log():
    action = request.json.get('action', '')
    user = request.json.get('user', '')
    # BAD: Unsanitized user input in log — CRLF injection
    logger.info(f"AUDIT: user={user} action={action}")
    return jsonify({'logged': True})

# ============================================================================
# REACHABLE: CWE-614 — Insecure Cookie (no Secure/HttpOnly)
# ============================================================================
@app.route('/api/auth/session', methods=['POST'])
def create_session():
    resp = make_response(jsonify({'status': 'authenticated'}))
    # BAD: Session cookie without Secure, HttpOnly, SameSite
    resp.set_cookie('session_id', 'abc123xyz', httponly=False, secure=False)
    resp.set_cookie('auth_token', 'tok_live_xxxxx', httponly=False)
    return resp

# ============================================================================
# UNREACHABLE variants
# ============================================================================
def _dead_info_leak():
    import os
    return dict(os.environ)

def _dead_log_password():
    logger.info("password=hunter2")

if __name__ == '__main__':
    app.run(port=5005)
