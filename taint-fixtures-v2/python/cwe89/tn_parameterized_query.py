# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: sql_parameterized_query
# SOURCE: http_request (request.args)
# SINK: cursor.execute (parameterized)
# TAINT_HOPS: 1
# NOTES: Parameterized query — value is bound, not interpolated
import sqlite3
from flask import request


def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SAFE: parameterized query — user input is a bound parameter
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
