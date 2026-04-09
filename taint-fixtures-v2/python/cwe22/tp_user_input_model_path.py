# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: os_path_join_user_input
# SOURCE: function_parameter
# SINK: open
# TAINT_HOPS: 1
# NOTES: User input directly in os.path.join — classic traversal
import os

def load_model(model_name):
    # VULNERABLE: model_name could be '../../../etc/passwd'
    model_path = os.path.join('/models', model_name)
    with open(model_path, 'r') as f:
        return f.read()
