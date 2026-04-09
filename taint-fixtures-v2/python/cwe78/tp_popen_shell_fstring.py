# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: popen_shell_true_fstring
# SOURCE: function_parameter
# SINK: subprocess.Popen
# TAINT_HOPS: 1
# NOTES: Popen with shell=True and f-string
import subprocess

def preprocess_data(user_dataset_path):
    # VULNERABLE: shell=True + user input
    cmd = f"/bin/bash -c 'python preprocess.py --data {user_dataset_path}'"
    return subprocess.Popen(cmd, shell=True)
