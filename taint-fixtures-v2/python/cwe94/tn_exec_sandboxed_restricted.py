# Fixture: CWE-94 Code Injection - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: exec_with_restricted_globals
# SOURCE: llm_response
# SINK: exec
# TAINT_HOPS: 1
# NOTES: Sandboxed exec with restricted globals - blocks builtins, imports
import math

SAFE_GLOBALS = {"__builtins__": {}, "math": math, "abs": abs, "round": round}

def safe_calculate(expression: str) -> str:
    namespace = {}
    # SAFE: restricted globals block __import__, open, exec, eval, etc.
    exec(f"result = {expression}", SAFE_GLOBALS, namespace)
    return str(namespace.get("result"))
