# Copyright © 2026 Sthenos Security. All rights reserved.
"""NOT_REACHABLE: CWE — module NEVER imported by entrypoint."""

import subprocess
import os
import hashlib

def sql_injection_dead(db, user_input: str):
    """CWE-89: NOT_REACHABLE — this whole file is never imported."""
    db.execute(f"SELECT * FROM users WHERE name='{user_input}'")

def path_traversal_dead(filename: str) -> str:
    """CWE-22: NOT_REACHABLE."""
    return open(os.path.join("/etc", filename)).read()

def weak_hash_dead(data: str) -> str:
    """CWE-327: NOT_REACHABLE — MD5."""
    return hashlib.md5(data.encode()).hexdigest()

def command_injection_dead(cmd: str) -> str:
    """CWE-78: NOT_REACHABLE."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
