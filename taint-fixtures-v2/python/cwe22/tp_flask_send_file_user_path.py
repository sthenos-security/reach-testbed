# Fixture: CWE-22 Path Traversal - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: flask_send_file_unvalidated
# SOURCE: request URL path
# SINK: send_file
# TAINT_HOPS: 1
# NOTES: Flask send_file with user-controlled filename - path traversal
from flask import Flask, send_file
import os

app = Flask(__name__)

@app.route("/download/<filename>")
def download(filename):
    filepath = os.path.join("/app/uploads", filename)
    # VULNERABLE: filename like ../../etc/passwd escapes uploads dir
    return send_file(filepath)
