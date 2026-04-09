# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: os_path_join_no_validation
# SOURCE: http_request (request.args)
# SINK: open (unvalidated path)
# TAINT_HOPS: 1
import os
from flask import request, send_file


def download_file():
    filename = request.args.get("filename")
    # VULNERABLE: CWE-22 · no validation that path stays within base dir
    filepath = os.path.join("/var/uploads", filename)
    return send_file(filepath)
