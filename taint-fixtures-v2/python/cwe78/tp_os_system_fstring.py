# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: os_system_fstring_user_input
# SOURCE: function_parameter
# SINK: os.system
# TAINT_HOPS: 1
# NOTES: os.system with f-string — direct shell RCE
import os

def train_model(user_model_name):
    # VULNERABLE: user input in shell command
    cmd = f"python train_model.py --model {user_model_name}"
    os.system(cmd)
