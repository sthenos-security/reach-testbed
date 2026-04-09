# Fixture: CWE-918 SSRF - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: urllib_urlopen_user_controlled
# SOURCE: function_parameter
# SINK: urllib.request.urlopen
# TAINT_HOPS: 1
# NOTES: User URL fetched via urllib - can access internal metadata endpoints
import urllib.request

def fetch_content(url: str) -> str:
    # VULNERABLE: user-controlled URL to urlopen
    response = urllib.request.urlopen(url)
    return response.read().decode()
