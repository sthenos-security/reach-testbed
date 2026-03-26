"""
Admin blueprint — NOT_REACHABLE (Type A).

This module IS imported in app.py, so its top-level code runs,
but the Blueprint is never registered via app.register_blueprint().
No endpoint in this Blueprint is reachable via HTTP.

CWE-78 (command injection) — NOT_REACHABLE: Blueprint never registered.
SECRET — NOT_REACHABLE: key defined but endpoint inaccessible.
"""
import subprocess
from flask import Blueprint, request, jsonify

admin_bp = Blueprint('admin', __name__)

# SECRET: Hardcoded admin key (NOT_REACHABLE — Blueprint never registered)
ADMIN_SECRET = "adm_live_flask_8kZp3Q"


@admin_bp.route('/admin/exec', methods=['POST'])
def admin_exec():
    """CWE-78 — NOT_REACHABLE (Type A): route defined but Blueprint never registered."""
    cmd = request.form.get('cmd', 'id')
    return jsonify({"output": subprocess.getoutput(cmd)})  # CWE-78 NOT_REACHABLE (Type A)


@admin_bp.route('/admin/token')
def admin_token():
    """SECRET — NOT_REACHABLE (Type A): endpoint inaccessible."""
    return jsonify({"token": ADMIN_SECRET})                # SECRET NOT_REACHABLE (Type A)
