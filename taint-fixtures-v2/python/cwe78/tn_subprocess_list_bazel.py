# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_list_form_build_tool
# SOURCE: none (literal list)
# SINK: subprocess.check_output
# TAINT_HOPS: 0
# NOTES: TensorFlow-style — hardcoded list form, no shell interpretation
# REAL_WORLD: tensorflow/tensorflow configure.py
import subprocess, sys

def run_shell(cmd, allow_non_zero=False):
    if allow_non_zero:
        try:
            output = subprocess.check_output(cmd, stderr=sys.stdout)
        except subprocess.CalledProcessError as e:
            output = e.output
    else:
        output = subprocess.check_output(cmd, stderr=sys.stdout)
    return output.decode('UTF-8').strip()

def get_bazel_version():
    # SAFE: hardcoded list
    return run_shell(['/usr/bin/bazel', '--version'], allow_non_zero=True)
