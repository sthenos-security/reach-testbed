"""
Auth router — REACHABLE (included in main.py via include_router).

CVE-2024-33663 (python-jose) — REACHABLE: jwt.decode called from /api/login.
UNKNOWN: requests imported, only safe .get() called — vulnerable path not exercised.
"""
from fastapi import APIRouter, Body
import requests
from jose import jwt

router = APIRouter()

JWT_SECRET = "super-secret-jwt-key-testbed"


@router.post("/login")
async def login(token: str = Body(..., embed=True)):
    """CVE-2024-33663 (python-jose) — REACHABLE."""
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # CVE REACHABLE
    return {"user": payload.get("sub")}


@router.get("/upstream")
async def check_upstream():
    """UNKNOWN: requests imported but only safe .get() path used."""
    resp = requests.get("http://localhost:8000/api/health")  # UNKNOWN CVE path
    return {"upstream": resp.status_code}
