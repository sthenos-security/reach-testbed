# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: subprocess_format_string_user_input
# SOURCE: http_request (request.args)
# SINK: subprocess.run (shell=True)
# TAINT_HOPS: 1
import subprocess
from flask import request


def list_directory():
    path = request.args.get("path")
    # VULNERABLE: CWE-78 · format string with user input in shell
    cmd = "ls -la {}".format(path)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
