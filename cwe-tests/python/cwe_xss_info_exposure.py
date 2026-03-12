# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# CWE-79 (XSS), CWE-352 (CSRF), CWE-1275 (Cookie without flags)
# CWE-614 (Sensitive Cookie without Secure), CWE-200 (Info Exposure)
# ============================================================================
from flask import Flask, request, jsonify, make_response, render_template_string
import traceback

app = Flask(__name__)

# REACHABLE: CWE-79 — Reflected XSS
@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    return f"<h1>Results for: {query}</h1>"  # BAD: unescaped user input in HTML

@app.route('/api/profile/<username>')
def profile(username):
    return render_template_string(f"<div>Welcome {username}</div>")  # BAD: SSTI/XSS

@app.route('/api/error/display')
def display_error():
    msg = request.args.get('msg', '')
    return f'<div class="error">{msg}</div>'  # BAD: reflected XSS

# REACHABLE: CWE-200 — Information Exposure
@app.route('/api/debug/env')
def debug_env():
    import os
    return jsonify(dict(os.environ))  # BAD: leaks all env vars including secrets

@app.route('/api/debug/stack')
def debug_stack():
    try:
        raise ValueError("test")
    except Exception:
        return jsonify({'trace': traceback.format_exc()})  # BAD: stack trace to user

@app.route('/api/debug/config')
def debug_config():
    return jsonify({
        'db_url': app.config.get('SQLALCHEMY_DATABASE_URI', ''),
        'secret': app.config.get('SECRET_KEY', ''),
        'debug': app.debug,
    })  # BAD: exposes internal config

# REACHABLE: CWE-614/CWE-1275 — Insecure Cookie
@app.route('/api/login', methods=['POST'])
def login():
    resp = make_response(jsonify({'status': 'ok'}))
    resp.set_cookie('session_id', 'abc123')  # BAD: no Secure, HttpOnly, SameSite
    resp.set_cookie('auth_token', 'xyz789', httponly=False)  # BAD: accessible to JS
    return resp

# REACHABLE: CWE-209 — Error Message with Sensitive Info
@app.route('/api/db/query', methods=['POST'])
def db_query():
    import sqlite3
    query = request.json.get('q', '')
    try:
        conn = sqlite3.connect('/tmp/app.db')
        conn.execute(query)
    except Exception as e:
        return jsonify({'error': str(e), 'query': query}), 500  # BAD: leaks query + error

# UNREACHABLE
def _dead_xss():
    return f"<script>alert('{input()}')</script>"

def _dead_info_leak():
    import os
    return os.environ.get('DATABASE_PASSWORD')

if __name__ == '__main__':
    app.run(port=5005)
