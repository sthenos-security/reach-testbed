"""Python mixed registry demo app.

Imports from both public (requests, flask) and private (authlib, internal_sdk)
packages so reachctl call-graph analysis has real code paths to trace.
"""
from flask import Flask, jsonify, request
import requests
from authlib.integrations.requests_client import OAuth2Session
from internal_sdk import authenticate, get_config

app = Flask(__name__)
config = get_config()


@app.route("/health")
def health():
    return jsonify({"status": "ok", "region": config.get("region")})


@app.route("/proxy")
def proxy_request():
    """Fetch external URL — exercises requests (CVE target)."""
    url = request.args.get("url", "https://httpbin.org/get")
    resp = requests.get(url, timeout=10)
    return jsonify(resp.json())


@app.route("/oauth/token")
def get_token():
    """Exercise authlib (private mirror of public package)."""
    session = OAuth2Session(
        client_id="test-client",
        client_secret="test-secret",
        token_endpoint="https://example.com/oauth/token",
    )
    return jsonify({"client_id": session.client_id})


@app.route("/auth")
def auth_check():
    """Exercise internal-sdk (genuine private package)."""
    token = request.headers.get("Authorization", "")
    valid = authenticate(token)
    return jsonify({"authenticated": valid})


if __name__ == "__main__":
    app.run(debug=True)
