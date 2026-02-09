# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Triggers: Semgrep path-traversal, open-redirect, file-inclusion
# CWE-22 (Path Traversal), CWE-73 (External Control of Filename)
# ============================================================================
"""
Path traversal and file access vulnerabilities.
Both REACHABLE (routed) and UNREACHABLE (dead code) variants.
"""
from flask import Flask, request, jsonify, send_file, redirect
import os

app = Flask(__name__)

UPLOAD_DIR = "/var/uploads"
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png'}


# ============================================================================
# REACHABLE: CWE-22 — Path Traversal (direct file read)
# ============================================================================
@app.route('/api/files/read', methods=['GET'])
def read_file():
    """User-controlled path passed directly to open()."""
    filepath = request.args.get('path', '')
    # BAD: No path sanitization — ../../etc/passwd works
    with open(filepath, 'r') as f:
        content = f.read()
    return jsonify({'content': content})


# REACHABLE: CWE-22 — Path Traversal (os.path.join bypass)
@app.route('/api/files/download', methods=['GET'])
def download_file():
    """os.path.join doesn't prevent traversal with absolute paths."""
    filename = request.args.get('name', '')
    # BAD: os.path.join with absolute path input bypasses base dir
    filepath = os.path.join(UPLOAD_DIR, filename)
    return send_file(filepath)


# REACHABLE: CWE-22 — Path Traversal (send_file with user input)
@app.route('/api/reports/<path:report_name>', methods=['GET'])
def get_report(report_name):
    """send_file with path parameter — traversal via URL."""
    # BAD: Flask path converter allows slashes
    return send_file(f"/var/reports/{report_name}")


# ============================================================================
# REACHABLE: CWE-73 — External Control of File Name or Path
# ============================================================================
@app.route('/api/files/write', methods=['POST'])
def write_file():
    """User controls the filename for writing."""
    filename = request.json.get('filename', '')
    content = request.json.get('content', '')
    # BAD: User controls write destination
    dest = os.path.join(UPLOAD_DIR, filename)
    with open(dest, 'w') as f:
        f.write(content)
    return jsonify({'status': 'written', 'path': dest})


# REACHABLE: CWE-73 — Arbitrary file delete
@app.route('/api/files/delete', methods=['DELETE'])
def delete_file():
    """User-controlled path in os.remove."""
    filepath = request.args.get('path', '')
    # BAD: No validation on delete target
    os.remove(filepath)
    return jsonify({'status': 'deleted'})


# ============================================================================
# REACHABLE: CWE-601 — Open Redirect
# ============================================================================
@app.route('/api/redirect', methods=['GET'])
def open_redirect():
    """User controls redirect target URL."""
    target_url = request.args.get('url', '/')
    # BAD: Unvalidated redirect
    return redirect(target_url)


@app.route('/api/goto', methods=['GET'])
def goto_page():
    """Another redirect variant with header injection potential."""
    next_page = request.args.get('next', '')
    # BAD: Redirect to user-controlled URL
    return redirect(f"https://example.com/{next_page}")


# ============================================================================
# UNREACHABLE: Same patterns in dead code
# ============================================================================
def _dead_path_traversal():
    """UNREACHABLE — never called."""
    user_path = "../../etc/shadow"
    with open(user_path) as f:
        return f.read()


def _dead_file_delete():
    """UNREACHABLE — dead code."""
    os.remove("/etc/passwd")


if __name__ == '__main__':
    app.run(port=5002)
