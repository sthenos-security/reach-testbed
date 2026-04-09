# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: sqlalchemy_text_fstring
# SOURCE: http_request (request.args)
# SINK: session.execute(text()) with f-string
# TAINT_HOPS: 1
from flask import request
from sqlalchemy import text
from sqlalchemy.orm import Session


def find_user(session: Session):
    name = request.args.get("name")
    # VULNERABLE: CWE-89 · SQLAlchemy text() with f-string interpolation
    result = session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
    return result.fetchone()
