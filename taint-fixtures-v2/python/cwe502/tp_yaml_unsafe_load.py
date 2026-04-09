# Fixture: code_patch · CWE-502 Deserialization · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: yaml_unsafe_load
# SOURCE: function_parameter
# SINK: yaml.unsafe_load
# TAINT_HOPS: 1
# NOTES: CVE-2021-37678 (CVSS 9.3) — yaml.unsafe_load allows arbitrary code exec
# REAL_WORLD: tensorflow/tensorflow CVE-2021-37678
import yaml

def load_config(untrusted_yaml):
    # VULNERABLE: yaml.unsafe_load allows !!python/object RCE
    return yaml.unsafe_load(untrusted_yaml)
