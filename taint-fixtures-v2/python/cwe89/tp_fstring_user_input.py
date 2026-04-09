# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: sql_fstring_user_input
# SOURCE: http_request (request.args)
# SINK: cursor.execute (f-string)
# TAINT_HOPS: 1
import sqlite3
from flask import request


def search_users():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: CWE-89 · f-string interpolation with user input
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{name}%'")
    return cursor.fetchall()
