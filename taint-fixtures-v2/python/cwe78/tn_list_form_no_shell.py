# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_list_form_no_shell
# SOURCE: http_request (request.args)
# SINK: subprocess.run (shell=False, list form)
# TAINT_HOPS: 1
# NOTES: List form prevents shell metacharacter interpretation
import subprocess
from flask import request


def run_scan():
    target = request.args.get("target")
    # SAFE: list form with shell=False — arguments not interpreted by shell
    result = subprocess.run(
        ["nmap", "-sV", target], capture_output=True, text=True
    )
    return result.stdout
