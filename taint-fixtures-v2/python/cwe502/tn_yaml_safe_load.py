# Fixture: code_patch · CWE-502 Deserialization · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: yaml_safe_load
# SOURCE: function_parameter
# SINK: yaml.safe_load
# TAINT_HOPS: 1
# NOTES: safe_load prevents code execution — only basic types
import yaml

def load_config_safe(yaml_string):
    # SAFE: safe_load blocks !!python/object tags
    return yaml.safe_load(yaml_string)
