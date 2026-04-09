# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: inter_proc_config_sourced_no_taint
# SOURCE: config (app.config)
# SINK: subprocess.run (config-sourced, no user input)
# TAINT_HOPS: 2
# NOTES: No user input in chain — command sourced from server config
import subprocess
from flask import current_app


def get_scanner_path() -> str:
    """Returns server-controlled config value — not tainted."""
    return current_app.config["SCANNER_PATH"]


def run_scan() -> str:
    scanner = get_scanner_path()
    # SAFE: command path from server config — no user input in chain
    return subprocess.run(
        [scanner, "--scan", "--json"], capture_output=True, text=True
    ).stdout
