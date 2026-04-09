# Fixture: CWE-502 Deserialization - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: safetensors_format_no_code_exec
# SOURCE: function_parameter (file path)
# SINK: safetensors.load_file
# TAINT_HOPS: 1
# NOTES: safetensors format - no code execution, only tensor data
from safetensors import safe_open

def load_model_safe(model_path: str):
    # SAFE: safetensors format cannot execute code
    with safe_open(model_path, framework="pt") as f:
        return {k: f.get_tensor(k) for k in f.keys()}
