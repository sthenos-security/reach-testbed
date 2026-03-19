# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Framework: Django (class-based and function-based views, URL routing)
#
# CWE-89  SQL Injection
# CWE-78  OS Command Injection
# CWE-94  Code Injection (eval)
# CWE-22  Path Traversal
# CWE-79  XSS (mark_safe bypass)
# CWE-918 SSRF
#
# Entrypoint model: Django URL conf → view function/class
# urls.py registers path() → view, engine must resolve this to find
# REACHABLE functions. Django ORM usage = FALSE POSITIVE (parameterized).
# ============================================================================
"""
Django injection tests. Covers:
  - Function-based views (FBVs) — simple URL → function
  - Class-based views (CBVs) — URL → View.as_view() → dispatch → get/post
  - Django ORM (safe — must NOT flag as SQLi)
  - Raw SQL via cursor.execute with user input (TRUE POSITIVE)
  - Raw SQL via cursor.execute with parameterized query (FALSE POSITIVE)
"""
import os
import subprocess
import sqlite3

from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.utils.safestring import mark_safe
import requests


# ============================================================================
# FUNCTION-BASED VIEWS — entrypoint: urls.py path("sqli/", sqli_view)
# ============================================================================

def sqli_fbv_raw_concat(request):
    """CWE-89 TP: raw SQL + string concat — REACHABLE, attacker-controlled."""
    user_id = request.GET.get("id", "1")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = " + user_id)
        rows = cursor.fetchall()
    return JsonResponse({"rows": rows})


def sqli_fbv_parameterized(request):
    """CWE-89 FP: parameterized query — REACHABLE but NOT a vulnerability."""
    user_id = request.GET.get("id", "1")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
        rows = cursor.fetchall()
    return JsonResponse({"rows": rows})


def sqli_fbv_orm(request):
    """CWE-89 FP: Django ORM — REACHABLE but NOT a vulnerability (ORM handles escaping)."""
    # ORM usage — engine must not flag this as SQLi
    from django.contrib.auth.models import User
    name = request.GET.get("name", "")
    users = list(User.objects.filter(username=name).values("id", "username"))
    return JsonResponse({"users": users})


def cmd_fbv_reachable(request):
    """CWE-78 TP: OS command injection — REACHABLE, attacker-controlled."""
    filename = request.GET.get("file", "test.txt")
    result = subprocess.check_output(f"cat /tmp/{filename}", shell=True)
    return HttpResponse(result)


def eval_fbv_reachable(request):
    """CWE-94 TP: code injection via eval — REACHABLE."""
    expr = request.POST.get("expr", "1+1")
    result = eval(expr)  # noqa: S307
    return JsonResponse({"result": result})


def path_traversal_fbv(request):
    """CWE-22 TP: path traversal — REACHABLE."""
    filename = request.GET.get("file", "readme.txt")
    with open(f"/var/app/files/{filename}") as f:
        content = f.read()
    return HttpResponse(content)


def xss_mark_safe_fbv(request):
    """CWE-79 TP: XSS via mark_safe with user input — REACHABLE."""
    msg = request.GET.get("msg", "")
    # mark_safe tells Django not to escape — if user-controlled this is XSS
    return HttpResponse(mark_safe(f"<p>{msg}</p>"))


def ssrf_fbv(request):
    """CWE-918 TP: SSRF — user controls the URL — REACHABLE."""
    url = request.GET.get("url", "http://example.com")
    resp = requests.get(url, timeout=5)
    return HttpResponse(resp.content)


# Dead code — same patterns but NEVER registered in urls.py
def sqli_dead_code(request):  # NOT_REACHABLE
    user_id = request.GET.get("id")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return JsonResponse({})


# ============================================================================
# CLASS-BASED VIEWS — entrypoint: urls.py path("cbv/sqli/", SQLiView.as_view())
#
# Engine must trace: URL → as_view() → dispatch() → get()/post()
# This is the CBV resolution chain Django uses internally.
# ============================================================================

class SQLiCBV(View):
    """CWE-89 TP: SQLi in CBV.get() — REACHABLE via as_view() dispatch."""

    def get(self, request):
        user_id = request.GET.get("id", "1")
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM orders WHERE user_id = " + user_id)
            rows = cursor.fetchall()
        return JsonResponse({"rows": rows})


class CommandInjectionCBV(View):
    """CWE-78 TP: command injection in CBV.post() — REACHABLE."""

    def post(self, request):
        cmd = request.POST.get("cmd", "ls")
        out = subprocess.check_output(cmd, shell=True)
        return HttpResponse(out)


class PathTraversalCBV(View):
    """CWE-22 TP: path traversal in CBV — REACHABLE."""

    def get(self, request):
        path = request.GET.get("path", "data.txt")
        with open(f"/srv/files/{path}") as f:
            return HttpResponse(f.read())


class DeadCBV(View):
    """NOT_REACHABLE — never registered in urls.py."""

    def get(self, request):
        secret = "never_exposed_ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        return HttpResponse(secret)


# ============================================================================
# DJANGO REST FRAMEWORK (DRF) STYLE — @api_view decorator
# DRF is used by ~70% of Django projects for REST APIs.
# Engine must recognise @api_view as an HTTP entrypoint.
# ============================================================================

try:
    from rest_framework.decorators import api_view
    from rest_framework.response import Response as DRFResponse

    @api_view(["GET"])
    def drf_sqli_view(request):
        """CWE-89 TP: SQLi in DRF @api_view — REACHABLE."""
        user_id = request.query_params.get("id", "1")
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM products WHERE id = " + user_id)
            rows = cursor.fetchall()
        return DRFResponse({"rows": rows})

    @api_view(["POST"])
    def drf_cmd_view(request):
        """CWE-78 TP: command injection in DRF @api_view — REACHABLE."""
        cmd = request.data.get("cmd", "echo hi")
        out = subprocess.check_output(cmd, shell=True)
        return DRFResponse({"output": out.decode()})

    @api_view(["GET"])
    def drf_dead_view(request):  # NOT_REACHABLE — not in router.urls
        secret_key = "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        return DRFResponse({"key": secret_key})

except ImportError:
    pass  # DRF not installed — skip DRF test cases
