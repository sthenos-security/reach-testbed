# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: dead_code_unreachable_sink
# SOURCE: http_request (request.args)
# SINK: subprocess.run (unreachable code path)
# TAINT_HOPS: 1
# NOTES: Vulnerable code exists but is in unreachable code path
import subprocess
from flask import request


def handle_scan():
    target = request.args.get("target")
    # SAFE: vulnerable path is dead code (condition always False)
    if False:
        subprocess.run(f"nmap {target}", shell=True)
    # Actual code uses safe pattern
    return subprocess.run(
        ["nmap", "-sV", target], capture_output=True, text=True
    ).stdout
