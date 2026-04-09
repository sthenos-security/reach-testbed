# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: inter_proc_return_value_taint
# SOURCE: http_request (request.args)
# SINK: subprocess.run (taint via return value)
# TAINT_HOPS: 2
# NOTES: Taint propagates through return value of helper function
import subprocess
from flask import request


def get_target() -> str:
    """Returns tainted value from HTTP request."""
    return request.args.get("target")


def handle_scan():
    target = get_target()
    # VULNERABLE: CWE-78 · taint flows from get_target() return value
    return subprocess.run(
        f"nmap {target}", shell=True, capture_output=True, text=True
    ).stdout
