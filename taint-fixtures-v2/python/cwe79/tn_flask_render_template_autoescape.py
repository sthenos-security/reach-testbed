# Fixture: CWE-79 Cross-Site Scripting - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: jinja2_autoescaped_template
# SOURCE: request.args
# SINK: render_template
# TAINT_HOPS: 1
# NOTES: Flask render_template uses Jinja2 autoescaping by default - safe
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # SAFE: render_template auto-escapes variables in .html templates
    return render_template("greet.html", name=name)
