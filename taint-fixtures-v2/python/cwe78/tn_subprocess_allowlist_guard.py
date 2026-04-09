# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_allowlist_guard
# SOURCE: http_request (request.args)
# SINK: subprocess.run (shell=True)
# TAINT_HOPS: 1
# NOTES: Allowlist validation prevents arbitrary command execution
import subprocess
from flask import request

ALLOWED_TOOLS = {"nmap", "dig", "ping", "traceroute"}


def run_tool():
    tool = request.args.get("tool")
    target = request.args.get("target")
    if tool not in ALLOWED_TOOLS:
        raise ValueError("Tool not allowed")
    # SAFE: tool validated against allowlist before shell execution
    result = subprocess.run(
        f"{tool} {target}", shell=True, capture_output=True, text=True
    )
    return result.stdout
