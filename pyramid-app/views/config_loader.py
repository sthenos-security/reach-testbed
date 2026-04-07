"""
Config views — REACHABLE (wired via config.add_view in app.py).

CVE-2020-14343 (pyyaml unsafe load) — REACHABLE.
CWE-78 (command injection) — REACHABLE.
UNKNOWN: pypdf imported but only metadata read path used (no ReDoS trigger).
"""
import os
import yaml


def load_config_view(request):
    """CVE-2020-14343 (pyyaml) + CWE-78 — REACHABLE."""
    path = request.params.get("path", "/etc/app.yml")
    with open(path) as f:
        data = yaml.load(f, Loader=yaml.Loader)           # CVE REACHABLE
    # CWE-78: command injection — os.system with user input
    os.system(f"echo Loaded {path}")                       # CWE REACHABLE
    return {"config": data}


def health_view(request):
    """Safe endpoint. UNKNOWN: pypdf imported but safe metadata path only."""
    return {"status": "ok", "framework": "pyramid"}
