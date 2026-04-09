# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: env_var_with_hardcoded_suffix
# SOURCE: environment_variable
# SINK: os.path.join
# TAINT_HOPS: 0
# NOTES: Environment variable base with fixed suffix — common in ML serving
import os

def get_model_path():
    model_root = os.environ.get('TF_MODEL_ROOT', '/default/models')
    # SAFE: suffix is hardcoded
    return os.path.join(model_root, 'v1.0', 'model.pb')
