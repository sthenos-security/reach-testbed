# Copyright © 2026 Sthenos Security. All rights reserved.
"""
SECRET NOT REACHABLE TEST (Dead Code)
=====================================
This module is NOT imported from app.py.
Expected: Secrets should be marked as NOT_REACHABLE.

Contains hardcoded secrets that are NEVER used.
"""


# GitHub token - NOT REACHABLE (dead code)
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Slack webhook - NOT REACHABLE (dead code)
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Private key - NOT REACHABLE (dead code)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MbXktK7R8K3svqej
FakePrivateKeyForTestingPurposesOnlyNotARealKey1234567890ABCDEF
-----END RSA PRIVATE KEY-----"""


def send_slack_notification(message: str):
    """
    Send Slack notification - NEVER CALLED (dead code).
    """
    import requests
    requests.post(SLACK_WEBHOOK, json={"text": message})


def get_github_token() -> str:
    """
    Get GitHub token - NEVER CALLED (dead code).
    """
    return GITHUB_TOKEN


def sign_with_private_key(data: str) -> str:
    """
    Sign data with private key - NEVER CALLED (dead code).
    """
    # This would use the PRIVATE_KEY but it's never called
    return f"signed:{data}"


# Never executed
if __name__ == '__main__':
    print("Dead code secrets module")
