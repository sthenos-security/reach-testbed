"""UNKNOWN: CWE — module imported, safe function called, vulnerable function never reached."""

import subprocess, os

def safe_render(text: str) -> str:
    """Safe function — called from entrypoint. No CWE here."""
    return text.replace("<", "&lt;").replace(">", "&gt;")

def unsafe_render_unknown(user_input: str) -> str:
    """
    CWE-78 UNKNOWN: OS injection here. Module IS imported but this function
    is NEVER called from entrypoint. Scanner must show UNKNOWN (not NOT_REACHABLE —
    the module is on the import graph — and not REACHABLE — this func has no call path).
    """
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout

def path_traversal_unknown(filename: str) -> str:
    """CWE-22 UNKNOWN: same module, never called."""
    return open(os.path.join("/var/data", filename)).read()
