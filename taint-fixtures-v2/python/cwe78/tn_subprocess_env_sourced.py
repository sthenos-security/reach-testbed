# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_env_sourced_command
# SOURCE: environment (os.environ)
# SINK: subprocess.run (shell=False)
# TAINT_HOPS: 1
# NOTES: Environment variables are server-controlled, not user-controlled
import os
import subprocess


def run_build():
    build_cmd = os.environ.get("BUILD_COMMAND", "make")
    # SAFE: command sourced from server environment, not user input
    result = subprocess.run(
        [build_cmd, "all"], capture_output=True, text=True
    )
    return result.stdout
