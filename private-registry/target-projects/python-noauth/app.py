"""Negative test: Python project WITHOUT private registry auth.
requests/flask resolve from public PyPI.
internal-sdk CANNOT be resolved — no devpi configured in pip.conf.
"""
from flask import Flask, jsonify
import requests

# This import would fail — internal-sdk not available without devpi
try:
    from internal_sdk import authenticate, get_config
except ImportError:
    authenticate = lambda t: False
    get_config = lambda: {"env": "missing", "region": "none"}

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/proxy")
def proxy_request():
    resp = requests.get("https://httpbin.org/get", timeout=10)
    return jsonify(resp.json())

if __name__ == "__main__":
    app.run(debug=True)
