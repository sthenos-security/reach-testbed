# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: sql_string_concat_user_input
# SOURCE: http_request (request.args)
# SINK: cursor.execute (string concat)
# TAINT_HOPS: 1
import sqlite3
from flask import request


def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: CWE-89 · string concatenation with user input
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
