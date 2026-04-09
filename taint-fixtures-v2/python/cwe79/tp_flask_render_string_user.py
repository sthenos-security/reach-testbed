# Fixture: CWE-79 Cross-Site Scripting - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: flask_render_template_string_user_input
# SOURCE: request.args
# SINK: render_template_string
# TAINT_HOPS: 1
# NOTES: Flask render_template_string with user data - classic SSTI/XSS
# REAL_WORLD: Common Flask anti-pattern
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # VULNERABLE: user input rendered directly in template
    return render_template_string("<h1>Hello " + name + "</h1>")
