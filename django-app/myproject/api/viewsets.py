"""
DRF ViewSet — REACHABLE (registered via router.register in urls.py).

CWE-89 — REACHABLE: SQL injection in custom @action.
"""
import sqlite3

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response


class UserViewSet(viewsets.ViewSet):
    """DRF ViewSet registered in urls.py via DefaultRouter.

    list() and retrieve() are auto-wired by the router.
    lookup() is wired via @action decorator.
    """

    def list(self, request):
        """GET /api/users/ — REACHABLE (auto-wired by router)."""
        return Response({"users": [{"id": 1, "name": "alice"}]})

    def retrieve(self, request, pk=None):
        """GET /api/users/{id}/ — REACHABLE (auto-wired by router)."""
        return Response({"id": pk, "name": "alice"})

    @action(detail=False, methods=['get'], url_path='lookup')
    def lookup(self, request):
        """GET /api/users/lookup/?name=... — REACHABLE (@action decorator).

        CWE-89: SQL injection in DRF custom action.
        """
        name = request.query_params.get("name", "")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (name TEXT, email TEXT)")
        # CWE-89: SQL injection via f-string in DRF @action
        rows = conn.execute(
            f"SELECT * FROM users WHERE name = '{name}'"    # CWE REACHABLE
        ).fetchall()
        conn.close()
        return Response({"results": rows})
