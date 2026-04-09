# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: percent_format_shell_true
# SOURCE: function_parameter
# SINK: subprocess.call
# TAINT_HOPS: 1
# NOTES: Old-style % formatting with shell=True
import subprocess

def build_gpu(gpu_id):
    # VULNERABLE: % format + shell=True
    cmd = "bazel build --config=gpu_%s" % gpu_id
    return subprocess.call(cmd, shell=True)
