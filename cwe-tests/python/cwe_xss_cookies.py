# Copyright © 2026 Sthenos Security. All rights reserved.
# CWE-79 (XSS), CWE-352 (CSRF), CWE-1275 (Cookie without flags)
from flask import Flask, request, jsonify, make_response, render_template_string

app = Flask(__name__)

# REACHABLE: CWE-79 — Reflected XSS
@app.route('/api/greet', methods=['GET'])
def greet():
    name = request.args.get('name', 'World')
    return f"<html><body><h1>Hello {name}!</h1></body></html>"

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    return render_template_string(f"<html><body>Results for: {query}</body></html>")

@app.route('/api/error', methods=['GET'])
def error_page():
    msg = request.args.get('msg', '')
    return f'<div class="error">{msg}</div>', 400

# REACHABLE: CWE-79 — Stored XSS (via template)
@app.route('/api/comment', methods=['POST'])
def post_comment():
    comment = request.json.get('body', '')
    html = render_template_string("<p>{{ comment }}</p>", comment=comment)
    return html  # Actually safe due to Jinja2 autoescaping, but pattern triggers

@app.route('/api/profile/bio', methods=['POST'])
def update_bio():
    bio = request.json.get('bio', '')
    return render_template_string(f"<div class='bio'>{bio}</div>")  # BAD: f-string, no escaping

# REACHABLE: CWE-1275 — Cookie without Secure/HttpOnly
@app.route('/api/login', methods=['POST'])
def login():
    resp = make_response(jsonify({'status': 'ok'}))
    resp.set_cookie('session_id', 'abc123')  # BAD: no secure, httponly, samesite
    return resp

@app.route('/api/preferences', methods=['POST'])
def set_prefs():
    resp = make_response(jsonify({'status': 'saved'}))
    resp.set_cookie('prefs', request.json.get('prefs', ''), httponly=False, secure=False)
    return resp

# REACHABLE: CWE-942 — Permissive CORS
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # BAD: wildcard CORS
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# UNREACHABLE
def _dead_xss():
    return f"<script>alert('{None}')</script>"
def _dead_cookie():
    resp = make_response("dead")
    resp.set_cookie('dead_session', 'x')
    return resp

if __name__ == '__main__':
    app.run(port=5005)
