"""
Parse router — REACHABLE (included in main.py via include_router).

CVE-2022-42969 (pypdf) — REACHABLE: called from POST /api/parse.
CWE-22 (path traversal) — REACHABLE: unsanitized file path.
SECRET — REACHABLE: hardcoded API key used in response.
"""
from fastapi import APIRouter, UploadFile, Query
from pypdf import PdfReader

router = APIRouter()

# SECRET: Hardcoded API key (REACHABLE — used in parse_document)
INTERNAL_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"


@router.post("/parse")
async def parse_document(file: UploadFile):
    """CVE-2022-42969 (pypdf ReDoS) — REACHABLE."""
    reader = PdfReader(file.file)                           # CVE REACHABLE
    text = "".join(p.extract_text() or "" for p in reader.pages)
    return {"text": text, "key": INTERNAL_API_KEY}          # SECRET REACHABLE


@router.get("/file")
async def read_file(path: str = Query(...)):
    """CWE-22 (path traversal) — REACHABLE: unsanitized path from query param."""
    with open(path) as f:                                   # CWE REACHABLE
        return {"content": f.read()}
