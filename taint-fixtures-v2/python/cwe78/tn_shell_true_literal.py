# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_shell_true_literal_only
# SOURCE: none (literal string)
# SINK: subprocess.run (shell=True)
# TAINT_HOPS: 0
# NOTES: shell=True but command is fully literal — no user input
import subprocess


def restart_service():
    # SAFE: fully literal command string
    result = subprocess.run(
        "systemctl restart nginx", shell=True, capture_output=True, text=True
    )
    return result.stdout
