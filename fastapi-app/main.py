"""
FastAPI application — entrypoint.

Routes included via app.include_router() are REACHABLE.
Routers defined but never included are NOT_REACHABLE.
"""
from fastapi import FastAPI

from routers.parse import router as parse_router
from routers.auth import router as auth_router

# NOTE: dead/unused_router.py defines a router but it is NEVER included here.

app = FastAPI(title="Testbed FastAPI App")

app.include_router(parse_router, prefix="/api")
app.include_router(auth_router, prefix="/api")


@app.get("/api/health")
def health():
    """Safe endpoint — no vulnerabilities."""
    return {"status": "ok"}
