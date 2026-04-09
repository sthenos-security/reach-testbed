# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: sql_int_cast_sanitizes_input
# SOURCE: http_request (request.args)
# SINK: cursor.execute (f-string)
# TAINT_HOPS: 1
# NOTES: int() cast neutralizes injection — can only be a number
import sqlite3
from flask import request


def get_user_by_id():
    user_id = int(request.args.get("id"))
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SAFE: int() cast ensures user_id is numeric — no injection possible
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
