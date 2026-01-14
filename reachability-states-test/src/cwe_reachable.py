"""
CWE REACHABLE TEST
==================
This module IS imported and called from app.py.
Expected: CWE issues should be marked as REACHABLE.

Contains:
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
"""
from jinja2 import Template


def render_user_input(user_input: str) -> str:
    """
    Render user input without escaping.
    This IS called from app.py - CWE should be REACHABLE.
    
    CWE-79: XSS - User input rendered without sanitization
    """
    # Vulnerable: no autoescape, direct user input
    template = Template("<div>{{ content }}</div>")
    return template.render(content=user_input)


def get_user_by_name(db_conn, username: str):
    """
    SQL Injection vulnerability - also reachable.
    
    CWE-89: SQL Injection
    """
    # Vulnerable: string formatting in SQL query
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def format_html(data: dict) -> str:
    """
    Another XSS vulnerability.
    
    CWE-79: Reflected XSS
    """
    # Vulnerable: direct string interpolation
    return f"<h1>{data.get('title', '')}</h1><p>{data.get('body', '')}</p>"
