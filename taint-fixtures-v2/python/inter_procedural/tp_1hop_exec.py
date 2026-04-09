# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: inter_proc_1hop_taint_propagation
# SOURCE: http_request (request.args)
# SINK: subprocess.run (via intermediate function)
# TAINT_HOPS: 2
# NOTES: Taint propagates through 1 intermediate function call
import subprocess
from flask import request


def execute(cmd: str) -> str:
    """Intermediate function — receives tainted input."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def handle_scan():
    target = request.args.get("target")
    # VULNERABLE: CWE-78 · user input flows through execute() to shell
    return execute(f"nmap -sV {target}")
