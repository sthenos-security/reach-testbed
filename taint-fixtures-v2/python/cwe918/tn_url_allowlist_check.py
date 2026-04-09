# Fixture: CWE-918 SSRF - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: url_domain_allowlist
# SOURCE: function_parameter
# SINK: requests.get (validated)
# TAINT_HOPS: 1
# NOTES: URL validated against domain allowlist before fetch
import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = {"api.github.com", "api.gitlab.com", "registry.npmjs.org"}

def fetch_package_info(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not allowed: {parsed.hostname}")
    # SAFE: only trusted domains
    return requests.get(url).json()
