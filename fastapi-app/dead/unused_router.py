"""
Dead router — NOT_REACHABLE.

This router is defined but NEVER included via app.include_router() in main.py.
All findings here should be NOT_REACHABLE.
"""
import sqlite3
from fastapi import APIRouter, Query
from pypdf import PdfReader

router = APIRouter()

# SECRET: Dead credential (NOT_REACHABLE — router never included)
DEAD_DB_PASSWORD = "postgres://admin:SuperSecret123@db.internal:5432/prod"


@router.post("/dead-parse")
async def dead_parse(data: bytes):
    """CVE-2022-42969 (pypdf) — NOT_REACHABLE: router not included."""
    reader = PdfReader(data)
    return {"pages": len(reader.pages)}


@router.get("/dead-query")
async def dead_query(q: str = Query(...)):
    """CWE-89 — NOT_REACHABLE: router not included."""
    conn = sqlite3.connect(":memory:")
    rows = conn.execute(f"SELECT * FROM t WHERE x = '{q}'").fetchall()
    return {"rows": rows}
