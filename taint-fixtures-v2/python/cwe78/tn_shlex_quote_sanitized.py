# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_shlex_quote_sanitized
# SOURCE: http_request (request.args)
# SINK: subprocess.run (shell=True)
# TAINT_HOPS: 1
# NOTES: shlex.quote sanitizes shell metacharacters
import shlex
import subprocess
from flask import request


def run_scan():
    target = request.args.get("target")
    safe_target = shlex.quote(target)
    # SAFE: shlex.quote escapes all shell metacharacters
    result = subprocess.run(
        f"nmap -sV {safe_target}", shell=True, capture_output=True, text=True
    )
    return result.stdout
