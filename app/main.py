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

@app.get("/api/items/list")
async def api_items_list(menu: str | None = None):
    # Menu-scoped listing: loader passes ?menu=<slug> baked in at build
    # time (MENU_SLUG constant), so one loader never sees another
    # product's payloads. Legacy clients that omit the arg see all.
    lines = []
    for it in store.list_items_metadata(menu_slug=menu):
        name = (it["name"] or "").replace("|", " ").replace("\n", " ")
        desc = (it["description"] or "").replace("|", " ").replace("\n", " ")
        version = (it["version"] or "").replace("|", " ").replace("\n", " ")
        has_img = "1" if it["has_image"] else "0"
        cur = "1" if it["is_current"] else "0"
        lines.append(
            f"{it['id']}|{has_img}|{it['size']}|{cur}|"
            f"{name}|{version}|{desc}")
    return Response(content="\n".join(lines) + "\n",
                    media_type="text/plain")

@app.get("/api/menus/list")
async def api_menus_list():
    # Public menu listing (slug|name|description per line). Only used by
    # the admin dashboard preview and future tooling; the loader itself
    # has its MENU_SLUG baked in at compile time.
    lines = []
    for m in store.list_menus():
        slug = (m["slug"] or "").replace("|", " ").replace("\n", " ")
        name = (m["name"] or "").replace("|", " ").replace("\n", " ")
        desc = (m["description"] or "").replace("|", " ").replace("\n", " ")
        lines.append(f"{slug}|{name}|{desc}")
    return Response(content="\n".join(lines) + "\n",
                    media_type="text/plain")

@app.get("/api/menus/{slug}/current")
async def api_menu_current(slug: str):
    # Loader uses this for "just inject whatever's current" without
    # having to parse the full item list.
    iid = store.current_item_for_menu(slug)
    if iid is None:
        return Response(content=b"0", media_type="text/plain",
                        status_code=404)
    return Response(content=str(iid).encode("ascii"),
                    media_type="text/plain")

@app.get("/api/items/{item_id}/image")
async def api_item_image(item_id: int):
    img, mime = store.get_item_image(item_id)
    if img is None:
        return Response(status_code=404, content=b"",
                        media_type="application/octet-stream")
    return Response(content=img, media_type=mime)

trip_limiter = RateLimiter(max_hits=60, window_seconds=60)

@app.post("/api/protection_trip")
async def api_protection_trip(request: Request):
    ip = client_ip(request)
    if not trip_limiter.allow(ip):
        return Response(content=b"", media_type="application/octet-stream")
    body = await request.body()
    if len(body) > 4096:
        return Response(content=b"", media_type="application/octet-stream")
    try:
        import json as _json
        data = _json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return Response(content=b"", media_type="application/octet-stream",
                        status_code=400)
    key_hash_hex = str(data.get("key_hash", ""))[:64]
    reason = str(data.get("reason", ""))[:200]
    source = str(data.get("source", ""))[:40]
    hwid_hex = str(data.get("hwid", ""))[:128]
    account_id = 0
    if len(key_hash_hex) == 64:
        try:
            key_hash = bytes.fromhex(key_hash_hex)
            lic = store.find_license_by_hash(key_hash)
            if lic:
                account_id = lic.account_id
        except Exception:
            pass
    detail = (f"source={source or 'unknown'} "
              f"hwid={hwid_hex[:16] + '...' if hwid_hex else '-'} "
              f"reason={reason or '-'}")
    store.log_event("protection_trip", 0, account_id, ip, detail)
    return Response(content=b"ok", media_type="application/octet-stream")

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
