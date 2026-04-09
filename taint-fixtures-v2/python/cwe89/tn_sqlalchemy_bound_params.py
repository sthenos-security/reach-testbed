# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: sqlalchemy_text_bound_params
# SOURCE: http_request (request.args)
# SINK: session.execute(text()) with bound params
# TAINT_HOPS: 1
# NOTES: SQLAlchemy text() with named parameters — properly bound
from flask import request
from sqlalchemy import text
from sqlalchemy.orm import Session


def find_user(session: Session):
    name = request.args.get("name")
    # SAFE: SQLAlchemy text() with named parameter binding
    result = session.execute(
        text("SELECT * FROM users WHERE name = :name"), {"name": name}
    )
    return result.fetchone()
