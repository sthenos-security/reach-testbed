# Fixture: code_patch · CWE-502 Deserialization · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: torch_load_weights_only_true
# SOURCE: function_parameter (file path)
# SINK: torch.load
# TAINT_HOPS: 1
# NOTES: weights_only=True restricts to tensors/primitives — no code exec
import torch

def load_checkpoint_safe(path):
    # SAFE: weights_only=True prevents pickle code execution
    return torch.load(path, weights_only=True)
