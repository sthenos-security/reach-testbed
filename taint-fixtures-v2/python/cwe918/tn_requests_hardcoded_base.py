# Fixture: CWE-918 SSRF - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: requests_hardcoded_base_url
# SOURCE: none (literal)
# SINK: requests.get
# TAINT_HOPS: 0
# NOTES: Base URL is hardcoded, only path/params from user - safe
import requests

API_BASE = "https://api.github.com"

def get_user_repos(username: str) -> dict:
    # SAFE: base URL is hardcoded, username is in path only
    resp = requests.get(f"{API_BASE}/users/{username}/repos")
    return resp.json()
