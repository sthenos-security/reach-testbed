# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: inter_proc_field_taint_propagation
# SOURCE: http_request (request.json)
# SINK: subprocess.run (taint via object field)
# TAINT_HOPS: 2
# NOTES: Taint propagates through object field assignment
import subprocess
from dataclasses import dataclass
from flask import request


@dataclass
class ScanConfig:
    target: str = ""
    tool: str = "nmap"


def handle_scan():
    data = request.get_json()
    config = ScanConfig()
    config.target = data.get("target")  # taint stored in field
    # VULNERABLE: CWE-78 · taint stored in object field flows to shell
    return subprocess.run(
        f"{config.tool} -sV {config.target}",
        shell=True, capture_output=True, text=True
    ).stdout
