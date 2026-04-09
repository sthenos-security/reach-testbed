# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_config_sourced_command
# SOURCE: config (app.config)
# SINK: subprocess.run (shell=False)
# TAINT_HOPS: 1
# NOTES: Config values are server-controlled
import subprocess
from flask import current_app


def scan_with_tool():
    tool_path = current_app.config["SCANNER_PATH"]
    # SAFE: tool path from application config, not user input
    result = subprocess.run(
        [tool_path, "--scan"], capture_output=True, text=True
    )
    return result.stdout
