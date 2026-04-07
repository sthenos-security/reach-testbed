"""
Django views — REACHABLE (wired in urls.py).

CVE signals:
  - pypdf 3.1.0 (CVE-2022-42969) — called from parse_pdf → REACHABLE
  - pyyaml 5.4 (CVE-2020-14343) — called from load_config → REACHABLE

CWE signals:
  - CWE-89: SQL injection in SearchView.get() → REACHABLE
  - CWE-78: Command injection in load_config() → REACHABLE

SECRET signals:
  - AWS_ACCESS_KEY hardcoded and used in parse_pdf() → REACHABLE

UNKNOWN signals:
  - requests 2.28.0 (CVE-2023-32681): imported, but only safe get() called;
    vulnerable send() path not exercised → UNKNOWN
"""
import sqlite3
import subprocess

import requests
import yaml
from pypdf import PdfReader
from django.http import JsonResponse
from django.views import View

# ── SECRET: Hardcoded AWS credentials (REACHABLE — used in parse_pdf) ──
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def parse_pdf(request):
    """FBV: Parse uploaded PDF.

    CVE-2022-42969 (pypdf ReDoS) — REACHABLE: PdfReader called from route.
    SECRET — REACHABLE: AWS_ACCESS_KEY used in response header.
    """
    if request.method != 'POST':
        return JsonResponse({"error": "POST required"}, status=405)
    body = request.body
    reader = PdfReader(body)                              # CVE REACHABLE
    text = "".join(p.extract_text() or "" for p in reader.pages)
    resp = JsonResponse({"text": text, "pages": len(reader.pages)})
    resp["X-Processed-By"] = AWS_ACCESS_KEY               # SECRET REACHABLE
    return resp


def load_config(request):
    """FBV: Load YAML config.

    CVE-2020-14343 (pyyaml unsafe load) — REACHABLE: yaml.load called.
    CWE-78 (command injection) — REACHABLE: subprocess with shell=True.
    """
    config_path = request.GET.get("path", "/etc/app.yml")
    with open(config_path) as f:
        data = yaml.load(f, Loader=yaml.Loader)          # CVE REACHABLE
    # CWE-78: command injection — shell=True with user input
    subprocess.call(f"echo Loaded config from {config_path}", shell=True)  # CWE REACHABLE
    return JsonResponse({"config": data})


def health(request):
    """Safe endpoint — no vulnerabilities."""
    # UNKNOWN: requests is imported but only safe .get() used here
    resp = requests.get("http://localhost:8000/api/health")  # UNKNOWN CVE path
    return JsonResponse({"status": "ok", "upstream": resp.status_code})


class SearchView(View):
    """CBV: Class-based view wired via .as_view() in urls.py.

    CWE-89 (SQL injection) — REACHABLE: string concat in GET handler.
    """
    def get(self, request):
        query = request.GET.get("q", "")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS items (name TEXT)")
        # CWE-89: SQL injection via string concatenation
        rows = conn.execute(
            f"SELECT * FROM items WHERE name = '{query}'"   # CWE REACHABLE
        ).fetchall()
        conn.close()
        return JsonResponse({"results": rows})


# ═══════════════════════════════════════════════════════════════════
# TYPE B DEAD CODE — function in same file, never called from any
# route or view.  The module IS imported (via urls.py), but this
# function has no call path from any entrypoint.
# ═══════════════════════════════════════════════════════════════════

def dead_inline_export(request):
    """NOT_REACHABLE (Type B): defined in live module but never wired in urls.py.

    CWE-78 (command injection) — NOT_REACHABLE: no URL pattern calls this.
    """
    cmd = request.GET.get("cmd", "id")
    return JsonResponse({"out": subprocess.getoutput(cmd)})  # CWE-78 NOT_REACHABLE
