# Fixture: CWE-89 SQL Injection - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: multi_hop_dict_extraction_to_sql
# SOURCE: request.json
# SINK: cursor.execute
# TAINT_HOPS: 2
# NOTES: Taint flows through dict extraction and string formatting
import sqlite3
from flask import request

def search_users():
    data = request.get_json()
    username = data["username"]
    query = f"SELECT * FROM users WHERE name = '{username}'"
    conn = sqlite3.connect("app.db")
    # VULNERABLE: 2-hop taint: request.json -> data -> username -> query
    return conn.execute(query).fetchall()
