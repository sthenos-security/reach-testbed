# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: inter_proc_2hop_taint_propagation
# SOURCE: http_request (request.args)
# SINK: subprocess.run (via 2 intermediate functions)
# TAINT_HOPS: 3
# NOTES: Taint propagates through 2 intermediate function calls
import subprocess
from flask import request


def run_shell(cmd: str) -> str:
    """Final sink — executes the command."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def build_and_run(tool: str, target: str) -> str:
    """Intermediate — builds command and passes to sink."""
    cmd = f"{tool} {target}"
    return run_shell(cmd)


def handle_scan():
    target = request.args.get("target")
    # VULNERABLE: CWE-78 · taint flows: request → build_and_run → run_shell → shell
    return build_and_run("nmap -sV", target)
