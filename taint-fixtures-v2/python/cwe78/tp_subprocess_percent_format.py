# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: subprocess_percent_format_user_input
# SOURCE: http_request (request.args)
# SINK: subprocess.run (shell=True)
# TAINT_HOPS: 1
import subprocess
from flask import request


def grep_files():
    pattern = request.args.get("pattern")
    # VULNERABLE: CWE-78 · percent formatting with user input
    cmd = "grep -r '%s' /var/log/" % pattern
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
