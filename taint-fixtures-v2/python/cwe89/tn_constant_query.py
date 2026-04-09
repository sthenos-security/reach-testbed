# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: sql_fully_constant_query
# SOURCE: none (literal string)
# SINK: cursor.execute
# TAINT_HOPS: 0
# NOTES: Entirely static SQL — no variables at all
import sqlite3


def count_active_users():
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SAFE: fully literal SQL query
    cursor.execute("SELECT COUNT(*) FROM users WHERE active = 1")
    return cursor.fetchone()[0]
