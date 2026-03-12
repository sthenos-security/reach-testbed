# Copyright © 2026 Sthenos Security. All rights reserved.
"""
CWE NOT REACHABLE TEST (Dead Code)
==================================
This module is NOT imported from app.py.
Expected: CWE issues should be marked as NOT_REACHABLE.

Contains:
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
"""
import os
import subprocess


def run_command(cmd: str) -> str:
    """
    OS Command Injection vulnerability - DEAD CODE.
    This function is NEVER called.
    
    CWE-78: OS Command Injection
    """
    # Vulnerable: shell=True with user input
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def read_file(filename: str) -> str:
    """
    Path Traversal vulnerability - DEAD CODE.
    This function is NEVER called.
    
    CWE-22: Path Traversal
    """
    # Vulnerable: no path sanitization
    filepath = os.path.join("/var/data", filename)
    with open(filepath) as f:
        return f.read()


def execute_eval(code: str):
    """
    Code Injection via eval - DEAD CODE.
    
    CWE-94: Code Injection
    """
    # Vulnerable: eval with user input
    return eval(code)


# Never executed
if __name__ == '__main__':
    print("Dead code CWE module")
