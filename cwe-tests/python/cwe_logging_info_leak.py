# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# CWE-117 (Log Injection), CWE-532 (Sensitive Data in Logs)
# CWE-209 (Error Message Info Leak), CWE-200 (Information Exposure)
# ============================================================================
from flask import Flask, request, jsonify
import logging
import traceback
import sys
import os

app = Flask(__name__)
app.config['DEBUG'] = True  # CWE-489: Active Debug in Production
logger = logging.getLogger('app')

# ── REACHABLE: CWE-117 — Log Injection ─────────────────────────────────────
@app.route('/api/log/event', methods=['POST'])
def log_event():
    username = request.json.get('username', '')
    action = request.json.get('action', '')
    logger.info(f"User {username} performed action: {action}")
    return jsonify({'logged': True})

@app.route('/api/log/search', methods=['GET'])
def log_search():
    query = request.args.get('q', '')
    logger.warning(f"Search query: {query}")
    return jsonify({'results': []})

# ── REACHABLE: CWE-532 — Sensitive Data in Logs ───────────────────────────
@app.route('/api/auth/debug-login', methods=['POST'])
def debug_login():
    email = request.json.get('email', '')
    password = request.json.get('password', '')
    token = request.json.get('api_token', '')
    logger.info(f"Login attempt: email={email}, password={password}, token={token}")
    return jsonify({'status': 'ok'})

@app.route('/api/payment/process', methods=['POST'])
def process_payment():
    card_number = request.json.get('card', '')
    cvv = request.json.get('cvv', '')
    logger.info(f"Processing payment for card {card_number} cvv {cvv}")
    return jsonify({'status': 'processed'})

# ── REACHABLE: CWE-209 — Error Info Leak (stack traces) ───────────────────
@app.route('/api/unsafe/divide', methods=['GET'])
def unsafe_divide():
    a = int(request.args.get('a', '0'))
    b = int(request.args.get('b', '0'))
    try:
        result = a / b
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc(),
            'python_version': sys.version,
            'cwd': os.getcwd(),
            'env': dict(os.environ),
        }), 500

@app.route('/api/unsafe/query', methods=['GET'])
def unsafe_query():
    try:
        raise ValueError("DB connection failed: postgres://admin:s3cret@db.internal:5432/prod")
    except Exception as e:
        return jsonify({'error': str(e), 'type': type(e).__name__}), 500

# ── REACHABLE: CWE-200 — Information Exposure ─────────────────────────────
@app.route('/api/debug/info', methods=['GET'])
def debug_info():
    return jsonify({
        'python': sys.version,
        'platform': sys.platform,
        'path': sys.path,
        'env': {k: v for k, v in os.environ.items()},
        'cwd': os.getcwd(),
        'pid': os.getpid(),
    })

@app.route('/api/debug/config', methods=['GET'])
def debug_config():
    return jsonify({
        'database_url': 'postgres://admin:pr0d_pass@db.internal:5432/app',
        'redis_url': 'redis://:r3dis_pass@cache.internal:6379',
        'secret_key': app.secret_key,
        'debug': app.debug,
    })

# ── REACHABLE: CWE-489 — Debug Left Active ────────────────────────────────
@app.route('/api/debug/eval', methods=['POST'])
def debug_eval():
    code = request.json.get('code', '')
    result = eval(code)
    return jsonify({'result': str(result)})

# ── UNREACHABLE ─────────────────────────────────────────────────────────────
def _dead_log_injection():
    logger.critical(f"ADMIN ACCESS: user=admin\nINFO Legitimate log entry")

def _dead_info_leak():
    return {'db_password': 'never_reaches_here', 'api_key': 'dead_code_key'}

if __name__ == '__main__':
    app.run(port=5006, debug=True)
