# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: whitelist_key_to_fixed_path
# SOURCE: function_parameter
# SINK: dict_lookup
# TAINT_HOPS: 0
# NOTES: Model key whitelisted — maps to fixed path, no user path construction
def get_model_path(model_key):
    ALLOWED = {
        'bert': '/models/bert-base',
        'gpt2': '/models/gpt2-medium',
        'resnet': '/models/resnet50'
    }
    if model_key not in ALLOWED:
        raise ValueError(f"Unknown model: {model_key}")
    return ALLOWED[model_key]
