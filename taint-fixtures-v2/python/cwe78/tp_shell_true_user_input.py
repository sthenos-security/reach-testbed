# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: subprocess_shell_true_user_input
# SOURCE: http_request (request.args)
# SINK: subprocess.run (shell=True)
# TAINT_HOPS: 1
import subprocess
from flask import request


def run_scan():
    target = request.args.get("target")
    # VULNERABLE: CWE-78 · user input in shell command
    result = subprocess.run(
        f"nmap -sV {target}", shell=True, capture_output=True, text=True
    )
    return result.stdout
