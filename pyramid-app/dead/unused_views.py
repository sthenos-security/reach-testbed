"""
Dead views — NOT_REACHABLE.

These views use @view_config decorators but NO matching route is added in app.py.
Without a route, Pyramid never dispatches to them.
"""
import sqlite3
from pyramid.view import view_config


# SECRET: Dead credential (NOT_REACHABLE — no route)
DEAD_SENDGRID_KEY = "SG.deaddeaddeaddeaddeaddeaddead.deaddeaddeaddeaddeaddead"


@view_config(route_name='dead_search', renderer='json')
def dead_search_view(request):
    """CWE-89 — NOT_REACHABLE: no 'dead_search' route added in app.py."""
    q = request.params.get("q", "")
    conn = sqlite3.connect(":memory:")
    rows = conn.execute(f"SELECT * FROM items WHERE name = '{q}'").fetchall()
    return {"results": rows}


@view_config(route_name='dead_admin', renderer='json')
def dead_admin_view(request):
    """CWE-78 — NOT_REACHABLE: no 'dead_admin' route added in app.py."""
    import os
    cmd = request.params.get("cmd", "ls")
    os.system(cmd)
    return {"executed": cmd}
