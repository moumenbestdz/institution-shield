#!/usr/bin/env python3
"""
api.py - REST API for Institution Shield.

Install : pip install cryptography fastapi "uvicorn[standard]" "pydantic>=2"
Bootstrap first admin (once):  python api.py create-admin <username>
Run (dev):   python api.py
Run (prod):  uvicorn api:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips="<proxy-ip>"
             behind a TLS-terminating reverse proxy (nginx / Caddy). Set SHIELD_ENV=prod to hide /docs.

Endpoints
  GET  /health            public
  POST /login             public (rate limited)  -> bearer token
  POST /logout            any session
  POST /transactions      permission: write       -> risk score + allow/review/block
  GET  /audit/verify      permission: verify_log  -> audit-log integrity check
  POST /users             permission: manage_users -> creates user, returns TOTP secret once
"""
import getpass
import os
import sys
import threading
import time
from collections import defaultdict, deque

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from institution_shield import ROLES, AuthManager
from shield_storage import PersistentShield

PROD = os.environ.get("SHIELD_ENV") == "prod"
shield = PersistentShield()

app = FastAPI(
    title="Institution Shield API",
    docs_url=None if PROD else "/docs",
    redoc_url=None,
    openapi_url=None if PROD else "/openapi.json",
)


# ───────────── Rate limiting ─────────────
class RateLimiter:
    def __init__(self, limit: int, window: int):
        self.limit, self.window = limit, window
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


global_limiter = RateLimiter(limit=120, window=60)   # per IP, all endpoints
login_limiter = RateLimiter(limit=10, window=60)     # per IP, /login only


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


@app.middleware("http")
async def guard(request: Request, call_next):
    if not global_limiter.allow(client_ip(request)):
        shield.audit.write("RATE_LIMITED", "anonymous", {"ip": client_ip(request), "path": request.url.path})
        return JSONResponse({"detail": "too many requests"}, status_code=429)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# ───────────── Schemas (strict validation) ─────────────
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    otp: str = Field(pattern=r"^\d{6}$")


class TxIn(BaseModel):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    account: str = Field(min_length=1, max_length=64)
    amount: float = Field(gt=0, lt=1e12)
    dest: str | None = Field(default=None, max_length=64)


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: str


# ───────────── Auth dependency ─────────────
bearer = HTTPBearer(auto_error=False)


def require(permission: str):
    def dep(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
        if not creds:
            raise HTTPException(401, "missing token", headers={"WWW-Authenticate": "Bearer"})
        try:
            return shield.auth.authorize(creds.credentials, permission)
        except PermissionError as e:
            code = 401 if "session" in str(e) else 403
            raise HTTPException(code, str(e))
    return dep


# ───────────── Endpoints ─────────────
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginIn, request: Request):
    ip = client_ip(request)
    if not login_limiter.allow(ip):
        raise HTTPException(429, "too many login attempts")
    token = shield.auth.login(body.username, body.password, body.otp, ip)
    if not token:
        raise HTTPException(401, "invalid credentials")     # deliberately generic
    return {"access_token": token, "token_type": "bearer",
            "expires_in": AuthManager.SESSION_SECONDS}


@app.post("/logout")
def logout(creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not creds:
        raise HTTPException(401, "missing token")
    s = shield.auth.sessions.pop(creds.credentials, None)
    if s:
        shield.audit.write("LOGOUT", s["user"])
    return {"status": "logged out"}


tx_lock = threading.Lock()


@app.post("/transactions")
def submit_transaction(body: TxIn, user: str = Depends(require("write"))):
    with tx_lock:
        with shield.db.lock:
            exists = shield.db.db.execute(
                "SELECT 1 FROM transactions WHERE id=?", (body.id,)).fetchone()
        if exists:                                           # blocks replay / overwrite
            raise HTTPException(409, "duplicate transaction id")
        # server-side timestamp: clients cannot fake time to dodge off-hours/velocity rules
        tx = {**body.model_dump(), "ts": time.time(), "submitted_by": user}
        result = shield.monitor.evaluate(tx)
    return {"id": body.id, **result}


@app.get("/audit/verify")
def verify_audit(user: str = Depends(require("verify_log"))):
    ok, line = shield.audit.verify()
    shield.audit.write("AUDIT_VERIFIED", user, {"intact": ok})
    return {"intact": ok, "first_break_line": line}


@app.post("/users", status_code=201)
def create_user(body: UserIn, admin: str = Depends(require("manage_users"))):
    if body.role not in ROLES:
        raise HTTPException(422, f"role must be one of {sorted(ROLES)}")
    if body.username in shield.auth.users:
        raise HTTPException(409, "username already exists")
    secret = shield.auth.register(body.username, body.password, body.role)
    shield.audit.write("USER_CREATED_BY", admin, {"new_user": body.username, "role": body.role})
    return {"username": body.username, "role": body.role, "totp_secret": secret}


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "create-admin":
        pw = getpass.getpass("Password (12+ chars): ")
        print("TOTP secret (add to an authenticator app, shown once):",
              shield.auth.register(sys.argv[2], pw, "admin"))
    else:
        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=8000)
