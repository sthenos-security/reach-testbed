"""
Dead views — NOT_REACHABLE (Type C).

This file is NEVER imported from app.py or any other module.
It defines Flask-style view functions, but since no Blueprint
or direct import connects it to the application, nothing here
is reachable.

CVE-2022-42969 (pypdf) — NOT_REACHABLE: file never imported.
CWE-89 (SQL injection) — NOT_REACHABLE: file never imported.
SECRET — NOT_REACHABLE: file never imported.
"""
import sqlite3
from pypdf import PdfReader

# SECRET: Dead admin key (NOT_REACHABLE — file never imported)
DEAD_ADMIN_KEY = "sk_dead_flask_Np7Wq2xK8m"


def dead_parse_pdf(file_bytes):
    """NOT_REACHABLE (Type C): CVE-2022-42969 in file never imported."""
    reader = PdfReader(file_bytes)                         # CVE NOT_REACHABLE (Type C)
    return reader.pages


def dead_query(user_input):
    """NOT_REACHABLE (Type C): CWE-89 in file never imported."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (name TEXT)")
    return conn.execute(
        f"SELECT * FROM users WHERE name = '{user_input}'"  # CWE-89 NOT_REACHABLE (Type C)
    ).fetchall()
