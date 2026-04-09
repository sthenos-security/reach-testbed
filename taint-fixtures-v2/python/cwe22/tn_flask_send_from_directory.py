# Fixture: CWE-22 Path Traversal - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: flask_send_from_directory_safe
# SOURCE: request URL path
# SINK: send_from_directory
# TAINT_HOPS: 1
# NOTES: Flask send_from_directory validates path is within directory
from flask import Flask, send_from_directory

app = Flask(__name__)

@app.route("/download/<filename>")
def download(filename):
    # SAFE: send_from_directory checks for path traversal attempts
    return send_from_directory("/app/uploads", filename)
