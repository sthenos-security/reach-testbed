# Fixture: CWE-601 Open Redirect - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: redirect_url_validated_relative
# SOURCE: request.args
# SINK: redirect (validated)
# TAINT_HOPS: 1
# NOTES: Redirect URL validated to be relative path only
from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)

@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    parsed = urlparse(next_url)
    # SAFE: reject absolute URLs and those with netloc (external domains)
    if parsed.scheme or parsed.netloc:
        next_url = "/"
    return redirect(next_url)
