# Fixture: CWE-79 Cross-Site Scripting - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: markupsafe_escape_before_render
# SOURCE: request.args
# SINK: string concatenation to HTML
# TAINT_HOPS: 1
# NOTES: MarkupSafe escape() sanitizes user input before HTML embedding
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = escape(request.args.get("name", ""))
    # SAFE: escape() converts <, >, &, ", ' to HTML entities
    return f"<h1>Hello {name}</h1>"
