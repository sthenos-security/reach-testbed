# Fixture: CWE-918 SSRF - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: requests_get_user_controlled_url
# SOURCE: request.args
# SINK: requests.get
# TAINT_HOPS: 1
# NOTES: User-controlled URL passed directly to requests.get
# REAL_WORLD: Common webhook/proxy endpoint pattern
import requests
from flask import Flask, request as flask_request

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    url = flask_request.args.get("url")
    # VULNERABLE: user controls the URL - can hit internal services
    resp = requests.get(url)
    return resp.text
