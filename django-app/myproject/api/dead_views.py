"""
Dead views — NOT_REACHABLE.

These views exist in the api app but are NOT wired in any urlpatterns.
The scanner should classify all findings here as NOT_REACHABLE.
"""
import sqlite3

from pypdf import PdfReader
from django.http import JsonResponse


# SECRET: Dead credential (NOT_REACHABLE — never used from any route)
DEAD_STRIPE_KEY = "sk_test_FAKE_dead_NOT_A_REAL_KEY_000"


def dead_pdf_parser(request):
    """CVE-2022-42969 (pypdf) — NOT_REACHABLE: not in urlpatterns."""
    reader = PdfReader(request.body)
    return JsonResponse({"pages": len(reader.pages)})


def dead_sql_query(request):
    """CWE-89 — NOT_REACHABLE: not in urlpatterns."""
    q = request.GET.get("q", "")
    conn = sqlite3.connect(":memory:")
    rows = conn.execute(f"SELECT * FROM t WHERE x = '{q}'").fetchall()
    return JsonResponse({"rows": rows})
