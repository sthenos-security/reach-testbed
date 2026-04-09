# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: pathlib_resolve_check
# SOURCE: http_request (request.args)
# SINK: Path.read_bytes (validated path)
# TAINT_HOPS: 1
# NOTES: pathlib resolve() + is_relative_to() validation
from pathlib import Path
from flask import request, abort

BASE_DIR = Path("/var/uploads")


def download_file():
    filename = request.args.get("filename")
    filepath = (BASE_DIR / filename).resolve()
    # SAFE: resolve() + is_relative_to() ensures containment
    if not filepath.is_relative_to(BASE_DIR):
        abort(403)
    return filepath.read_bytes()
