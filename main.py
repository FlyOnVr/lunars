from __future__ import annotations

import os
import threading
import time

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import config as cfg
from . import protocol
from .db import Database
from .ratelimit import RateLimiter
from .store import SqliteStore
from .routes_admin import build_admin_router

_PROJECT_DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data"))
_FALLBACKS = (_PROJECT_DATA_DIR, "/tmp/license-server-data")

def _try_dir(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write_probe")
        with open(probe, "w") as f:
            f.write("ok")
        os.unlink(probe)
        return True
    except Exception:
        return False

def _resolve_data_dir() -> str:
    env = os.environ.get("LICENSE_DATA_DIR")
    candidates = []
    if env:
        candidates.append(os.path.abspath(env))
    for p in _FALLBACKS:
        if p not in candidates:
            candidates.append(p)
    for p in candidates:
        if _try_dir(p):
            if env and p != os.path.abspath(env):
                print(f"[warn] LICENSE_DATA_DIR={env!r} not writable; "
                      f"using {p!r} instead. Data will not survive redeploys "
                      f"unless a persistent disk is mounted at the configured "
                      f"path.", flush=True)
            return p
    raise RuntimeError(
        f"No writable data directory. Tried: {candidates!r}")

DATA_DIR = _resolve_data_dir()

app = FastAPI(title="License Server", docs_url=None, redoc_url=None, openapi_url=None)

db = Database(os.path.join(DATA_DIR, "license.db"))
appcfg = cfg.bootstrap(db, DATA_DIR)
store = SqliteStore(db, appcfg.app_secret, data_dir=DATA_DIR)

app.state.db = db
app.state.store = store
app.state.cfg = appcfg
app.state.data_dir = DATA_DIR

app.add_middleware(SessionMiddleware, secret_key=appcfg.cookie_secret,
                   same_site="lax", https_only=False)

login_ip_limiter = RateLimiter(max_hits=20, window_seconds=60)
login_key_limiter = RateLimiter(max_hits=10, window_seconds=60)
exchange_limiter = RateLimiter(max_hits=120, window_seconds=60)

def client_ip(request: Request) -> str:
    return request.client.host if request.client else "0.0.0.0"

@app.post("/api/login")
async def api_login(request: Request):
    ip = client_ip(request)
    if not login_ip_limiter.allow(ip):
        return Response(content=b"", media_type="application/octet-stream")
    body = await request.body()
    if len(body) > 4096:
        return Response(content=b"", media_type="application/octet-stream")
    key_part = bytes(body[49:]) if len(body) > 49 else b""
    if key_part and not login_key_limiter.allow(key_part.hex()):
        return Response(content=b"", media_type="application/octet-stream")

    resp = protocol.handle_login(store, appcfg.priv_key, body, ip)
    return Response(content=resp, media_type="application/octet-stream")

@app.post("/api/exchange")
async def api_exchange(request: Request):
    ip = client_ip(request)
    if not exchange_limiter.allow(ip):
        return Response(content=b"", media_type="application/octet-stream")
    body = await request.body()
    if len(body) != protocol.EXCHANGE_LEN:
        return Response(content=b"", media_type="application/octet-stream")
    resp = protocol.handle_exchange(store, appcfg.priv_key, body, ip)
    return Response(content=resp, media_type="application/octet-stream")

@app.get("/api/pubkey")
async def api_pubkey():
    return Response(content=appcfg.public_key_hex, media_type="text/plain")

@app.get("/healthz")
async def healthz():
    return {"ok": True}

app.include_router(build_admin_router())

_static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=_static_dir), name="static")

@app.get("/")
async def root():
    return Response(status_code=307, headers={"Location": "/admin"})

def _sweeper():
    while True:
        time.sleep(30)
        try:
            store.sweep()
        except Exception:
            pass

@app.on_event("startup")
def _start_sweeper():
    t = threading.Thread(target=_sweeper, daemon=True)
    t.start()
