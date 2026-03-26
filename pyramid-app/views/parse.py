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
