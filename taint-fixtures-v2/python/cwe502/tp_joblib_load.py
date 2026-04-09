# Fixture: code_patch · CWE-502 Deserialization · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: joblib_load_untrusted
# SOURCE: function_parameter (file path)
# SINK: joblib.load
# TAINT_HOPS: 1
# NOTES: joblib uses pickle internally — scikit-learn model loading RCE
import joblib

def load_sklearn_model(model_path):
    # VULNERABLE: joblib.load uses pickle
    return joblib.load(model_path)
