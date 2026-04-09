# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: inter_proc_guard_function_validates
# SOURCE: http_request (request.args)
# SINK: subprocess.run (guarded by validation)
# TAINT_HOPS: 2
# NOTES: Guard function validates input before it reaches the sink
import re
import subprocess
from flask import request, abort

IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def validate_target(target: str) -> str:
    """Guard — validates input is an IP address."""
    if not IP_REGEX.match(target):
        abort(400, "Invalid IP address")
    return target


def handle_scan():
    target = request.args.get("target")
    safe_target = validate_target(target)
    # SAFE: input validated as IP address by guard function
    return subprocess.run(
        f"ping -c 3 {safe_target}", shell=True, capture_output=True, text=True
    ).stdout
