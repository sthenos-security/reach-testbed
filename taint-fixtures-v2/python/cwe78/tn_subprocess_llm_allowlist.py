# Fixture: CWE-78 Command Injection - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_list_form_allowlisted_cmd
# SOURCE: llm_response (validated)
# SINK: subprocess.run
# TAINT_HOPS: 1
# NOTES: Agent tool with command allowlist + list form - safe
import subprocess

ALLOWED_CMDS = {"ls", "cat", "head", "wc", "grep"}

def safe_shell_tool(command: str, args: list) -> str:
    if command not in ALLOWED_CMDS:
        raise ValueError(f"Command not allowed: {command}")
    # SAFE: allowlist + list form prevents injection
    result = subprocess.run([command] + args, capture_output=True, text=True)
    return result.stdout
