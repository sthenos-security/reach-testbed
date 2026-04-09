# Fixture: code_patch · CWE-502 Deserialization · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: pickle_load_untrusted_file
# SOURCE: function_parameter (file path)
# SINK: pickle.load
# TAINT_HOPS: 1
# NOTES: pickle.load from untrusted source — classic RCE
import pickle

def load_model(model_path):
    # VULNERABLE: pickle can execute arbitrary code
    with open(model_path, 'rb') as f:
        return pickle.load(f)
