"""
CVE REACHABLE TEST
==================
This module IS imported and called from app.py.
Expected: CVE should be marked as REACHABLE.

Uses requests 2.25.0 which has:
- CVE-2021-33503 (urllib3 dependency)
- CVE-2023-32681 (requests itself)
"""
import requests


def fetch_data(url: str) -> dict:
    """
    Fetch data from URL.
    This function IS called from app.py, so the CVE should be REACHABLE.
    """
    response = requests.get(url, timeout=30)
    return response.json()


def fetch_with_auth(url: str, token: str) -> dict:
    """Another function using requests - also reachable if fetch_data is called."""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    return response.json()
