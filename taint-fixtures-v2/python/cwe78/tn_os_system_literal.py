# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: os_system_literal_only
# SOURCE: none (literal string)
# SINK: os.system
# TAINT_HOPS: 0
# NOTES: os.system with fully literal command — no user input
import os


def clear_cache():
    # SAFE: fully literal command
    os.system("rm -rf /tmp/cache/*")
