# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: sql_percent_format_user_input
# SOURCE: http_request (request.form)
# SINK: cursor.execute (% format)
# TAINT_HOPS: 1
import sqlite3
from flask import request


def delete_user():
    user_id = request.form.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: CWE-89 · percent formatting with user input
    cursor.execute("DELETE FROM users WHERE id = %s" % user_id)
    conn.commit()
