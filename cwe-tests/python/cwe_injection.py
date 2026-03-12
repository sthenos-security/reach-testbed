# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Triggers: Semgrep sql-injection, python-sql-injection, command-injection
# CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-94 (Code Injection)
# ============================================================================
"""
Tests for injection vulnerabilities. Contains both REACHABLE (called from
Flask routes) and UNREACHABLE (dead code) variants.
"""
from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os

app = Flask(__name__)

DB_PATH = "/tmp/testbed.db"

# ============================================================================
# REACHABLE: CWE-89 — SQL Injection (string concatenation)
# ============================================================================
@app.route('/api/users/search', methods=['GET'])
def search_users():
    """Direct string concatenation in SQL — classic SQLi."""
    username = request.args.get('name', '')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # BAD: String formatting in SQL query
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    results = cursor.fetchall()
    conn.close()
    return jsonify({'users': results})


# REACHABLE: CWE-89 — SQL Injection (f-string)
@app.route('/api/users/<int:user_id>/orders', methods=['GET'])
def get_user_orders(user_id):
    """f-string in SQL — another SQLi variant."""
    sort_col = request.args.get('sort', 'date')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # BAD: f-string in query (sort column injection)
    cursor.execute(f"SELECT * FROM orders WHERE user_id = ? ORDER BY {sort_col}", (user_id,))
    results = cursor.fetchall()
    conn.close()
    return jsonify({'orders': results})


# REACHABLE: CWE-89 — SQL Injection (format string)
@app.route('/api/products', methods=['GET'])
def search_products():
    """%-format in SQL query."""
    category = request.args.get('cat', '')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # BAD: %-format string
    cursor.execute("SELECT * FROM products WHERE category = '%s'" % category)
    results = cursor.fetchall()
    conn.close()
    return jsonify({'products': results})


# ============================================================================
# REACHABLE: CWE-78 — OS Command Injection
# ============================================================================
@app.route('/api/dns/lookup', methods=['GET'])
def dns_lookup():
    """User input directly in shell command."""
    hostname = request.args.get('host', '')
    # BAD: Shell injection via user input
    result = subprocess.check_output(f"nslookup {hostname}", shell=True)
    return jsonify({'result': result.decode()})


# REACHABLE: CWE-78 — OS Command Injection (os.system)
@app.route('/api/files/compress', methods=['POST'])
def compress_file():
    """os.system with user-controlled filename."""
    filename = request.json.get('filename', '')
    # BAD: os.system with user input
    os.system(f"tar czf /tmp/archive.tar.gz {filename}")
    return jsonify({'status': 'compressed'})


# REACHABLE: CWE-78 — OS Command Injection (os.popen)
@app.route('/api/network/ping', methods=['GET'])
def ping_host():
    """os.popen with user input."""
    target = request.args.get('target', '')
    # BAD: os.popen with user input
    result = os.popen(f"ping -c 1 {target}").read()
    return jsonify({'result': result})


# ============================================================================
# REACHABLE: CWE-94 — Code Injection (eval/exec)
# ============================================================================
@app.route('/api/calculate', methods=['POST'])
def calculate():
    """eval() on user input — direct code injection."""
    expression = request.json.get('expr', '')
    # BAD: eval on user-controlled input
    result = eval(expression)
    return jsonify({'result': str(result)})


@app.route('/api/template/render', methods=['POST'])
def render_template_unsafe():
    """exec() with user input — code injection via template."""
    template_code = request.json.get('template', '')
    context = {}
    # BAD: exec on user-controlled code
    exec(template_code, context)
    return jsonify({'result': str(context.get('output', ''))})


# ============================================================================
# UNREACHABLE: Same patterns but in dead code
# ============================================================================
def _dead_sqli():
    """UNREACHABLE SQL injection — never called from any route."""
    user_input = "admin' OR '1'='1"
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM sessions WHERE user = '" + user_input + "'")
    conn.close()


def _dead_command_injection():
    """UNREACHABLE command injection — no call path."""
    cmd = "rm -rf /"
    os.system(f"echo {cmd}")


def _dead_eval():
    """UNREACHABLE eval — dead code."""
    data = "__import__('os').system('whoami')"
    eval(data)


if __name__ == '__main__':
    app.run(port=5001)
