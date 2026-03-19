# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Framework: Django REST Framework — ViewSet / ModelViewSet / Router
#
# DRF ViewSets use a Router that auto-generates list/create/retrieve/update
# /destroy URL patterns. Engine must resolve:
#   router.register() → ViewSet → action methods (list, create, retrieve, ...)
#
# Also tests @action decorator (custom routes within ViewSets).
# ============================================================================
import os
import subprocess

from django.db import connection
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter


# ─── Serializer (safe — no injection surface here) ───────────────────────────

class UserSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField()


# ─── ViewSet — REACHABLE via router ──────────────────────────────────────────

class UserViewSet(viewsets.ViewSet):
    """
    All action methods below are REACHABLE — router registers this ViewSet.
    Engine must trace: router.register("users", UserViewSet) → each action.
    """

    def list(self, request):
        """CWE-89 TP: SQLi in DRF ViewSet.list() — REACHABLE."""
        search = request.query_params.get("search", "")
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, username FROM auth_user WHERE username LIKE '%" + search + "%'"
            )
            rows = cursor.fetchall()
        return Response({"users": rows})

    def create(self, request):
        """CWE-78 TP: command injection in ViewSet.create() — REACHABLE."""
        cmd = request.data.get("cmd", "echo hello")
        out = subprocess.check_output(cmd, shell=True)
        return Response({"output": out.decode()})

    def retrieve(self, request, pk=None):
        """CWE-89 TP: raw SQL in ViewSet.retrieve() — REACHABLE."""
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM auth_user WHERE id = {pk}")
            row = cursor.fetchone()
        return Response({"user": row})

    @action(detail=False, methods=["get"])
    def search_unsafe(self, request):
        """CWE-89 TP: @action custom route — REACHABLE via router + @action."""
        term = request.query_params.get("q", "")
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM products WHERE name = '" + term + "'"
            )
            rows = cursor.fetchall()
        return Response({"results": rows})

    @action(detail=False, methods=["get"])
    def search_safe(self, request):
        """CWE-89 FP: parameterized @action — REACHABLE but NOT a vulnerability."""
        term = request.query_params.get("q", "")
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM products WHERE name = %s", [term]
            )
            rows = cursor.fetchall()
        return Response({"results": rows})

    @action(detail=True, methods=["post"])
    def upload_file(self, request, pk=None):
        """CWE-22 TP: path traversal in @action — REACHABLE."""
        filename = request.data.get("filename", "data.csv")
        with open(f"/srv/uploads/{filename}") as f:
            content = f.read()
        return Response({"content": content})


class DeadViewSet(viewsets.ViewSet):
    """NOT_REACHABLE — never registered with router."""

    def list(self, request):
        secret = "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        return Response({"secret": secret})

    def create(self, request):
        cmd = request.data.get("cmd")
        os.system(cmd)
        return Response({"ok": True})


# ─── Router registration — engine must read this to build entrypoint set ─────

router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")
# DeadViewSet intentionally NOT registered
