"""
Admin router — NOT_REACHABLE (Type A).

This router IS imported in main.py, but never passed to
app.include_router().  The module is loaded, so its top-level
code runs, but no endpoint is reachable via HTTP.

CWE-78 (command injection) — NOT_REACHABLE: route exists but is
never mounted.
SECRET — NOT_REACHABLE: key defined but endpoint inaccessible.
"""
import subprocess
from fastapi import APIRouter, Query

router = APIRouter()

# SECRET: Hardcoded admin token (NOT_REACHABLE — router never mounted)
ADMIN_TOKEN = "adm_live_9fZ83kLpQwXy2mN7"


@router.post("/admin/exec")
async def admin_exec(cmd: str = Query(...)):
    """CWE-78 — NOT_REACHABLE (Type A): route defined but router never include_router()'d."""
    return {"output": subprocess.getoutput(cmd)}           # CWE-78 NOT_REACHABLE (Type A)


@router.get("/admin/token")
async def admin_token():
    """SECRET — NOT_REACHABLE (Type A): returns token but route is unreachable."""
    return {"token": ADMIN_TOKEN}                          # SECRET NOT_REACHABLE (Type A)
