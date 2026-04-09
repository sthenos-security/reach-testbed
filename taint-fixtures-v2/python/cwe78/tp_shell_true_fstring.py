# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: shell_true_fstring_interpolation
# SOURCE: function_parameter
# SINK: subprocess.call
# TAINT_HOPS: 1
# NOTES: shell=True + f-string = RCE. user_flag could be 'opt; rm -rf /'
import subprocess

def vulnerable_build(user_build_flag):
    # VULNERABLE: f-string + shell=True
    cmd = f"bazel build {user_build_flag}"
    return subprocess.call(cmd, shell=True)
