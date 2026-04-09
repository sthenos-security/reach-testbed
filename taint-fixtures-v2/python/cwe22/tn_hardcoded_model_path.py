# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: hardcoded_path_no_user_input
# SOURCE: none (literal)
# SINK: open
# TAINT_HOPS: 0
# NOTES: TensorFlow-style — fully hardcoded model paths, no user input
# REAL_WORLD: tensorflow/tensorflow model serving patterns
import os

def load_model_config():
    MODEL_DIR = '/var/models/tensorflow'
    model_path = os.path.join(MODEL_DIR, 'saved_model', 'model.pb')
    # SAFE: fully hardcoded path
    with open(model_path, 'r') as f:
        return f.read()
