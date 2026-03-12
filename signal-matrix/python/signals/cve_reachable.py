# Copyright © 2026 Sthenos Security. All rights reserved.
"""REACHABLE stubs — called from entrypoint.py."""
import requests

def fetch_user_data(uid: int) -> dict:
    # CVE-2023-32681: requests redirect handling — REACHABLE
    resp = requests.get(f"https://api.example.com/users/{uid}")
    return resp.json()
