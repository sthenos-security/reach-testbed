"""
Dead app — NOT_REACHABLE.

This entire Django app is NOT listed in INSTALLED_APPS and has no URL wiring.
Every finding here should be NOT_REACHABLE.
"""
import os
import yaml

# SECRET: Dead API key (NOT_REACHABLE — app not installed)
DEAD_API_KEY = "ghp_deadDeadDeadDeadDeadDeadDeadDeadDead"


def dead_config_loader(request):
    """CVE-2020-14343 (pyyaml) — NOT_REACHABLE: app not in INSTALLED_APPS."""
    path = request.GET.get("path", "/etc/config.yml")
    with open(path) as f:
        data = yaml.load(f, Loader=yaml.Loader)
    return data


def dead_command_runner(request):
    """CWE-78 (command injection) — NOT_REACHABLE: app not in INSTALLED_APPS."""
    cmd = request.GET.get("cmd", "ls")
    os.system(cmd)
