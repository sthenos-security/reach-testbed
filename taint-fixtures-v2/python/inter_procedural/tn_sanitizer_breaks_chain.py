# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: inter_proc_sanitizer_breaks_taint
# SOURCE: http_request (request.args)
# SINK: subprocess.run (taint broken by sanitizer)
# TAINT_HOPS: 2
# NOTES: shlex.quote in intermediate function breaks taint chain
import shlex
import subprocess
from flask import request


def sanitize_input(value: str) -> str:
    """Sanitizer — breaks taint chain."""
    return shlex.quote(value)


def handle_scan():
    target = request.args.get("target")
    safe_target = sanitize_input(target)
    # SAFE: taint broken by shlex.quote sanitizer in intermediate function
    return subprocess.run(
        f"nmap -sV {safe_target}", shell=True, capture_output=True, text=True
    ).stdout
