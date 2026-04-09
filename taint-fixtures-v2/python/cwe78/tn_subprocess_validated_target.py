# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_validated_format_check
# SOURCE: function_parameter (validated)
# SINK: subprocess.run
# TAINT_HOPS: 1
# NOTES: Build target validated against character allowlist before subprocess
import subprocess

def build_target(target):
    if not target or not all(c.isalnum() or c in '/_:-' for c in target):
        raise ValueError("Invalid target format")
    # SAFE: validated + list form
    return subprocess.run(['bazel', 'build', f'//tensorflow:{target}', '--config=opt'],
                          capture_output=True)
