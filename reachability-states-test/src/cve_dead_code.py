"""
CVE NOT REACHABLE TEST (Dead Code)
==================================
This module is NOT imported from app.py.
Expected: CVE should be marked as NOT_REACHABLE.

Uses pyyaml 5.3.1 which has:
- CVE-2020-14343 (unsafe yaml.load)
"""
import yaml


def parse_config(config_str: str) -> dict:
    """
    Parse YAML config using unsafe load.
    This function is NEVER called - it's dead code.
    Expected: CVE should be NOT_REACHABLE.
    """
    # Unsafe yaml.load - CVE-2020-14343
    return yaml.load(config_str, Loader=yaml.FullLoader)


def process_yaml_file(filepath: str) -> dict:
    """Another dead code function."""
    with open(filepath) as f:
        return yaml.load(f, Loader=yaml.UnsafeLoader)


# This code exists but is never imported or called
if __name__ == '__main__':
    # Only runs if executed directly, but this file is never executed
    print("This dead code module was run directly")
