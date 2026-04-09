# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: os_system_user_input
# SOURCE: http_request (request.form)
# SINK: os.system
# TAINT_HOPS: 1
import os
from flask import request


def ping_host():
    host = request.form.get("host")
    # VULNERABLE: CWE-78 · os.system always uses shell
    os.system(f"ping -c 3 {host}")
