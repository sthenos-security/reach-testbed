# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: os_realpath_startswith_check
# SOURCE: http_request (request.args)
# SINK: open (validated path)
# TAINT_HOPS: 1
# NOTES: os.path.realpath resolves symlinks and .., then startswith validates
import os
from flask import request, send_file, abort

BASE_DIR = "/var/uploads"


def download_file():
    filename = request.args.get("filename")
    filepath = os.path.join(BASE_DIR, filename)
    real_path = os.path.realpath(filepath)
    # SAFE: realpath resolves traversal, startswith validates containment
    if not real_path.startswith(BASE_DIR):
        abort(403)
    return send_file(real_path)
