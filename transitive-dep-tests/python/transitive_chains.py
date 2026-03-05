"""
Transitive Dependency Reachability Test Cases
==============================================
INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
Copyright © 2026 Sthenos Security. Test file only.

Tests that REACHABLE correctly classifies CVEs in transitive dependencies:

Chain A (depth-2, REACHABLE):
  app.py → requests (direct, safe) → urllib3 (transitive, CVE-2021-33503)
  Expected: urllib3 CVE marked REACHABLE (call path goes through requests)

Chain B (depth-2, NOT_REACHABLE):
  app.py imports but never calls the requests chain
  Expected: urllib3 CVE marked NOT_REACHABLE

Chain C (depth-3, REACHABLE):
  app.py → boto3 (direct) → botocore (transitive L1) → urllib3 (transitive L2)
  Expected: urllib3 CVE marked REACHABLE via boto3 call path

Chain D (diamond dependency, REACHABLE):
  app.py → flask (direct) → werkzeug (transitive)
           → requests (direct) → urllib3 (transitive)
  Both paths reach urllib3 — should be REACHABLE

Chain E (depth-2, mixed):
  Some functions call the vulnerable transitive dep, others don't.
  Expected: per-function reachability classification.
"""

# =============================================================================
# Chain A: Direct dep (requests) → Transitive dep (urllib3) — REACHABLE
# CVE-2021-33503: urllib3 ReDoS in Location header parsing
# =============================================================================

import requests  # direct dep — urllib3 is its transitive dep


def fetch_url_reachable(url: str) -> dict:
    """
    REACHABLE transitive CVE path:
    fetch_url_reachable() → requests.get() → urllib3.HTTPConnectionPool
    urllib3 CVE-2021-33503 should be marked REACHABLE.
    """
    response = requests.get(url, timeout=30)  # triggers urllib3 transitive dep
    return response.json()


def post_data_reachable(url: str, payload: dict) -> int:
    """Second REACHABLE path through urllib3 via requests.post()."""
    response = requests.post(url, json=payload, timeout=30)
    return response.status_code


# =============================================================================
# Chain B: Import only — urllib3 NOT called through any live path
# =============================================================================

import requests as _requests_unused  # noqa: F811


def dead_code_urllib3_path():
    """
    NOT_REACHABLE: This function imports requests but is never called.
    urllib3 transitive CVE should be NOT_REACHABLE for this path.
    Dead code — not imported or called from any entrypoint.
    """
    _response = _requests_unused.get("http://example.com")
    return _response.status_code


# =============================================================================
# Chain C: depth-3 transitive — boto3 → botocore → urllib3
# =============================================================================

import boto3  # direct dep → botocore (L1 transitive) → urllib3 (L2 transitive)


def upload_to_s3_reachable(bucket: str, key: str, data: bytes) -> bool:
    """
    REACHABLE depth-3 transitive path:
    upload_to_s3_reachable() → boto3.client() → botocore → urllib3
    CVE in urllib3 should be REACHABLE at depth 3.
    """
    client = boto3.client("s3")
    client.put_object(Bucket=bucket, Key=key, Body=data)
    return True


def list_buckets_reachable() -> list:
    """Another depth-3 REACHABLE path."""
    client = boto3.client("s3")
    response = client.list_buckets()
    return [b["Name"] for b in response.get("Buckets", [])]


# =============================================================================
# Chain D: Diamond dependency — two direct deps both depend on urllib3
# flask → werkzeug; requests → urllib3 (both paths converge on urllib3)
# =============================================================================

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/proxy", methods=["POST"])
def proxy_request_reachable():
    """
    REACHABLE via diamond: flask route + requests call.
    Both werkzeug (via flask) and urllib3 (via requests) are transitive.
    """
    target_url = request.json.get("url")
    response = requests.get(target_url, timeout=10)  # urllib3 path
    return jsonify({"status": response.status_code, "body": response.text})


# =============================================================================
# Chain E: Mixed reachability within same module
# Some functions call transitive dep, others don't
# =============================================================================

def mixed_reachable_function(url: str) -> str:
    """REACHABLE: calls requests → urllib3."""
    return requests.get(url).text


def mixed_not_reachable_function():
    """
    NOT_REACHABLE: imports requests but never called from any entrypoint.
    This function is defined but not wired to any route or import.
    """
    import requests as r
    return r.get("http://example.com").status_code


# =============================================================================
# requirements.txt equivalent — what a real app would declare
# These are the DIRECT deps; transitive deps come with them:
#
#   requests==2.28.0       # direct — urllib3==1.26.x is transitive (CVE-2021-33503)
#   boto3==1.26.0          # direct — botocore→urllib3 (depth-2 transitive)
#   flask==2.2.0           # direct — werkzeug is transitive
#   pyyaml==5.3.1          # direct — CVE-2020-14343 (direct dep vuln)
# =============================================================================
