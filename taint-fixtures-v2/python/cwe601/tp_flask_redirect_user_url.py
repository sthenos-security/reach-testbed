# Fixture: CWE-601 Open Redirect - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: flask_redirect_user_controlled_url
# SOURCE: request.args
# SINK: redirect
# TAINT_HOPS: 1
# NOTES: User-controlled URL in redirect - can send to phishing site
# REAL_WORLD: Common post-login redirect pattern
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    # ... authenticate user ...
    # VULNERABLE: user controls redirect target - can be https://evil.com
    return redirect(next_url)
