# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: popen_shell_user_input
# SOURCE: http_request (request.json)
# SINK: subprocess.Popen (shell=True)
# TAINT_HOPS: 1
import subprocess
from flask import request


def execute_command():
    data = request.get_json()
    cmd = data.get("command")
    # VULNERABLE: CWE-78 · Popen with shell=True and user input
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return proc.communicate()[0]
