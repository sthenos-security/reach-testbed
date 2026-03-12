# Copyright © 2026 Sthenos Security. All rights reserved.
"""REACHABLE: CWE — called from entrypoint."""
import subprocess
from jinja2 import Template

def render_template_unsafe(user_input: str) -> str:
    """CWE-79: XSS via Jinja2 without autoescape — REACHABLE."""
    return Template("<div>{{ content }}</div>").render(content=user_input)

def execute_query(q: str) -> list:
    """CWE-89: SQL injection — REACHABLE."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    rows = conn.execute(f"SELECT * FROM t WHERE name='{q}'").fetchall()
    return rows
