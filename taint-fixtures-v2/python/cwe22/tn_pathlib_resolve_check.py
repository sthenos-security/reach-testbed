# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: pathlib_resolve_startswith
# SOURCE: function_parameter
# SINK: pathlib.Path.read_text
# TAINT_HOPS: 1
# NOTES: Proper path validation with resolve() + startswith check
from pathlib import Path

def load_model_safe(requested_model):
    SAFE_BASE = Path('/models').resolve()
    requested_path = (Path('/models') / requested_model).resolve()
    if not str(requested_path).startswith(str(SAFE_BASE)):
        raise ValueError("Path traversal detected")
    return requested_path.read_text()
