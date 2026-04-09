# Fixture: CWE-78 Command Injection - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: multi_hop_fstring_to_subprocess
# SOURCE: request.args
# SINK: subprocess.run
# TAINT_HOPS: 2
# NOTES: Taint flows through intermediate variable and string formatting
import subprocess
from flask import request

def deploy():
    branch = request.args.get("branch")
    cmd = f"git checkout {branch}"
    full_cmd = f"cd /app && {cmd}"
    # VULNERABLE: 2-hop taint: request -> cmd -> full_cmd -> subprocess
    subprocess.run(full_cmd, shell=True)
