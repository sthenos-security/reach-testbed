# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# INVOCATION PATTERNS TEST — Case 1: External Endpoint
#
# All functions are REACHABLE via HTTP routes.
# Variables are ATTACKER_CONTROLLED (user input flows to sink).
#
# Expected:
#   app_reachability = REACHABLE (call graph finds @app.route → function)
#   taint_verdict    = ATTACKER_CONTROLLED (AI sees request.args → sink)
# ============================================================================
"""Case 1: External HTTP endpoint → vulnerable function."""
from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os

app = Flask(__name__)


# ── CWE-89: SQL Injection via HTTP endpoint ──────────────────────────────

@app.route('/case1/sqli', methods=['GET'])
def case1_sqli():
    """REACHABLE + ATTACKER_CONTROLLED: request param → SQL."""
    user_id = request.args.get('id', '')
    conn = sqlite3.connect(':memory:')
    conn.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    conn.close()
    return jsonify({'status': 'ok'})


# ── CWE-78: Command Injection via HTTP endpoint ─────────────────────────

@app.route('/case1/cmdi', methods=['POST'])
def case1_cmdi():
    """REACHABLE + ATTACKER_CONTROLLED: request body → shell."""
    cmd = request.json.get('cmd', 'ls')
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({'output': result.stdout})


# ── CWE-22: Path Traversal via HTTP endpoint ────────────────────────────

@app.route('/case1/path', methods=['GET'])
def case1_path_traversal():
    """REACHABLE + ATTACKER_CONTROLLED: request param → file read."""
    filename = request.args.get('file', '')
    path = os.path.join('/var/data', filename)
    with open(path) as f:
        return jsonify({'content': f.read()})


# ── CWE-918: SSRF via HTTP endpoint ─────────────────────────────────────

@app.route('/case1/ssrf', methods=['GET'])
def case1_ssrf():
    """REACHABLE + ATTACKER_CONTROLLED: request param → URL fetch."""
    import urllib.request
    url = request.args.get('url', '')
    data = urllib.request.urlopen(url).read()
    return jsonify({'size': len(data)})


if __name__ == '__main__':
    app.run(port=5010)
