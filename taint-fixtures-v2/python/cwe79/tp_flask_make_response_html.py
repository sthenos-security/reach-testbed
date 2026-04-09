# Fixture: CWE-79 Cross-Site Scripting - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: make_response_html_concat
# SOURCE: request.args
# SINK: make_response
# TAINT_HOPS: 1
# NOTES: Flask make_response with HTML string containing user input
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULNERABLE: user input in HTML response body
    html = f"<html><body>Results for: {query}</body></html>"
    return make_response(html)
