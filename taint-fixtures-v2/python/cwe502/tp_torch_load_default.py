# Fixture: code_patch · CWE-502 Deserialization · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: torch_load_no_weights_only
# SOURCE: function_parameter (file path)
# SINK: torch.load
# TAINT_HOPS: 1
# NOTES: torch.load uses pickle by default — RCE if untrusted checkpoint
import torch

def load_checkpoint(path):
    # VULNERABLE: torch.load uses pickle internally
    return torch.load(path)
