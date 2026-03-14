# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# INVOCATION PATTERNS TEST — Case 3: Dead Code
#
# These functions are NEVER called — not from HTTP routes, not from threads,
# not from init, not from anywhere. The module itself is NOT imported by any
# entrypoint.
#
# Expected:
#   app_reachability = NOT_REACHABLE (call graph finds no path)
#   taint_verdict    = N/A (analyzer skips NOT_REACHABLE findings)
# ============================================================================
"""Case 3: Dead code — functions that never execute."""
import os
import sqlite3
import subprocess


def dead_sqli(user_input: str):
    """CWE-89: SQL injection — but NEVER called.
    NOT_REACHABLE: no import path, no internal trigger.
    """
    conn = sqlite3.connect(':memory:')
    conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    conn.close()


def dead_cmdi(cmd: str):
    """CWE-78: Command injection — but NEVER called.
    NOT_REACHABLE: no import path, no internal trigger.
    """
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def dead_path_traversal(filename: str):
    """CWE-22: Path traversal — but NEVER called.
    NOT_REACHABLE: no import path, no internal trigger.
    """
    path = os.path.join('/var/data', filename)
    with open(path) as f:
        return f.read()


def dead_ssrf(url: str):
    """CWE-918: SSRF — but NEVER called.
    NOT_REACHABLE: no import path, no internal trigger.
    """
    import urllib.request
    return urllib.request.urlopen(url).read()


def dead_eval(code: str):
    """CWE-94: Code injection — but NEVER called.
    NOT_REACHABLE: no import path, no internal trigger.
    """
    return eval(code)


# This file has NO:
# - Flask/FastAPI routes
# - threading/Timer calls
# - atexit/signal hooks
# - module-level function calls
# - class instantiation
# It is pure dead code.
