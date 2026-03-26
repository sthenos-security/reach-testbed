"""
Parse view — REACHABLE (wired via config.add_view in app.py).

CVE-2022-42969 (pypdf) — REACHABLE: PdfReader called.
SECRET — REACHABLE: hardcoded key used in response.
"""
from pypdf import PdfReader

# SECRET: Hardcoded API key (REACHABLE — used in parse_pdf_view)
PARSE_API_KEY = "sk_live_pyramid_testbed_key_example"


def parse_pdf_view(request):
    """CVE-2022-42969 (pypdf ReDoS) — REACHABLE."""
    body = request.body
    reader = PdfReader(body)                               # CVE REACHABLE
    text = "".join(p.extract_text() or "" for p in reader.pages)
    return {"text": text, "pages": len(reader.pages), "key": PARSE_API_KEY}


# ═══════════════════════════════════════════════════════════════════
# TYPE B DEAD CODE — function in same file as live view, but never
# wired via config.add_view() in app.py.  Module IS imported.
# ═══════════════════════════════════════════════════════════════════

import subprocess

def dead_inline_parse(request):
    """NOT_REACHABLE (Type B): in live module but no config.add_view for it.

    CWE-78 (command injection) — NOT_REACHABLE.
    """
    return {"out": subprocess.getoutput(request.params.get("cmd", "id"))}  # CWE-78 NOT_REACHABLE
