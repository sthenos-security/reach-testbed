# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Framework: FastAPI
#
# CWE-89  SQL Injection
# CWE-78  OS Command Injection
# CWE-22  Path Traversal
# CWE-79  XSS (HTMLResponse with unescaped input)
# CWE-918 SSRF
# CWE-502 Deserialization (pickle)
#
# FastAPI entrypoint model:
#   @app.get / @app.post / @router.get  →  function
#   APIRouter registered with app.include_router()
#   Path parameters, Query parameters, Request body (Pydantic model)
#
# Key differences from Flask the engine must handle:
#   1. Type-annotated parameters — int/str annotations affect injection surface
#   2. Pydantic request bodies — fields are user-controlled
#   3. async def routes — same signal model as sync
#   4. APIRouter — sub-router registered with include_router()
#   5. Depends() — dependency injection chain, user input flows through it
# ============================================================================
import pickle
import sqlite3
import subprocess

import httpx
from fastapi import APIRouter, Depends, FastAPI, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI()
router = APIRouter(prefix="/api/v2")


# ─── Pydantic models — fields are user-controlled inputs ─────────────────────

class SearchRequest(BaseModel):
    query: str
    limit: int = 10

class CommandRequest(BaseModel):
    cmd: str

class FileRequest(BaseModel):
    filename: str

class URLRequest(BaseModel):
    url: str

class DataRequest(BaseModel):
    data: str   # base64-encoded, for deserialization test


# ─── Dependency injection — engine must follow Depends() chain ───────────────

def get_db():
    """Dependency: yields a sqlite3 connection. User input flows through caller."""
    conn = sqlite3.connect("/tmp/testbed.db")
    try:
        yield conn
    finally:
        conn.close()


# ─── Routes on main app ───────────────────────────────────────────────────────

@app.get("/sqli/path/{user_id}")
def sqli_path_param(user_id: str):
    """CWE-89 TP: SQLi via path param (str) — REACHABLE."""
    conn = sqlite3.connect("/tmp/testbed.db")
    conn.execute("SELECT * FROM users WHERE id = " + user_id)
    return {"ok": True}


@app.get("/sqli/path-safe/{user_id}")
def sqli_path_param_safe(user_id: int):
    """CWE-89 FP: int-annotated path param — FastAPI enforces int, parameterized — REACHABLE, not injectable."""
    conn = sqlite3.connect("/tmp/testbed.db")
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return {"ok": True}


@app.get("/sqli/query")
def sqli_query_param(name: str = Query(...)):
    """CWE-89 TP: SQLi via Query() param — REACHABLE."""
    conn = sqlite3.connect("/tmp/testbed.db")
    conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return {"ok": True}


@app.post("/sqli/body")
def sqli_body(req: SearchRequest):
    """CWE-89 TP: SQLi via Pydantic body field — REACHABLE."""
    conn = sqlite3.connect("/tmp/testbed.db")
    conn.execute("SELECT * FROM products WHERE name LIKE '%" + req.query + "%'")
    return {"ok": True}


@app.post("/sqli/body-depends")
def sqli_depends(req: SearchRequest, db=Depends(get_db)):
    """CWE-89 TP: SQLi with Depends() chain — REACHABLE. Engine must follow Depends()."""
    db.execute("SELECT * FROM products WHERE name = '" + req.query + "'")
    return {"ok": True}


@app.post("/cmd")
def cmd_injection(req: CommandRequest):
    """CWE-78 TP: OS command injection via POST body — REACHABLE."""
    out = subprocess.check_output(req.cmd, shell=True)
    return {"output": out.decode()}


@app.post("/path")
def path_traversal(req: FileRequest):
    """CWE-22 TP: path traversal via Pydantic body — REACHABLE."""
    with open(f"/srv/files/{req.filename}") as f:
        return {"content": f.read()}


@app.get("/xss")
def xss_html(msg: str = Query(default="")):
    """CWE-79 TP: XSS via HTMLResponse with unescaped query param — REACHABLE."""
    return HTMLResponse(content=f"<html><body><p>{msg}</p></body></html>")


@app.post("/ssrf")
def ssrf(req: URLRequest):
    """CWE-918 TP: SSRF — user-controlled URL — REACHABLE."""
    resp = httpx.get(req.url)
    return {"status": resp.status_code}


@app.post("/deserialize")
def unsafe_deserialize(req: DataRequest):
    """CWE-502 TP: unsafe pickle deserialization of user input — REACHABLE."""
    import base64
    data = base64.b64decode(req.data)
    obj = pickle.loads(data)  # noqa: S301
    return {"type": str(type(obj))}


# ─── APIRouter — engine must follow include_router() to find these ───────────

@router.get("/sqli")
async def router_sqli(term: str = Query(...)):
    """CWE-89 TP: async route on APIRouter — REACHABLE via include_router."""
    conn = sqlite3.connect("/tmp/testbed.db")
    conn.execute("SELECT * FROM items WHERE tag = '" + term + "'")
    return {"ok": True}


@router.post("/cmd")
async def router_cmd(req: CommandRequest):
    """CWE-78 TP: async cmd injection on APIRouter — REACHABLE."""
    import asyncio
    proc = await asyncio.create_subprocess_shell(
        req.cmd,
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    return {"output": stdout.decode()}


@router.get("/dead-secret")
async def router_dead_secret():
    """NOT_REACHABLE — this router is not registered with app (see bottom)."""
    api_key = "AKIAIOSFODNN7EXAMPLE"
    return {"key": api_key}


# Register sub-router — engine must parse this to find routes above
app.include_router(router)
# A second dead_router intentionally NOT included


# ─── Unrouted function — NOT_REACHABLE ───────────────────────────────────────

def unrouted_sqli(name: str):
    """NOT_REACHABLE — plain function, no decorator, not called anywhere."""
    conn = sqlite3.connect("/tmp/testbed.db")
    conn.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return {}
