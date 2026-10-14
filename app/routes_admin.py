from __future__ import annotations

import os
import time

from fastapi import APIRouter, Form, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from . import config as cfg
from . import crypto

_templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "templates")
)

def _fmt_ts(v):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(v)))
    except Exception:
        return ""

_templates.env.filters["ts"] = _fmt_ts

def _authed(request: Request) -> bool:
    return bool(request.session.get("admin"))

def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)

def build_admin_router() -> APIRouter:
    router = APIRouter(prefix="/admin")

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if _authed(request):
            return _redirect("/admin")
        return _templates.TemplateResponse("login.html", {"request": request, "error": None})

    @router.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request, username: str = Form(...),
                           password: str = Form(...)):
        c = request.app.state.cfg
        ok = (crypto.constant_time_eq(username.encode(), c.admin_username.encode())
              and crypto.verify_password(password, c.admin_password_hash))
        if not ok:
            time.sleep(0.4)
            return _templates.TemplateResponse(
                "login.html", {"request": request, "error": "Invalid credentials"},
                status_code=401,
            )
        request.session["admin"] = True
        return _redirect("/admin")

    @router.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return _redirect("/admin/login")

    @router.get("", response_class=HTMLResponse)
    @router.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        return _templates.TemplateResponse("dashboard.html", {
            "request": request,
            "counts": store.counts(),
            "pubkey": request.app.state.cfg.public_key_hex,
            "events": store.list_events(limit=15),
        })

    @router.get("/items", response_class=HTMLResponse)
    async def items_page(request: Request, menu: int | None = None):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        return _templates.TemplateResponse("items.html", {
            "request": request,
            "items": store.list_items(menu),
            "menus": store.list_menus(),
            "current_menu_id": menu,
        })

    @router.post("/items/upload")
    async def items_upload(request: Request, name: str = Form(...),
                           version: str = Form(""),
                           entry_point: str = Form(""),
                           description: str = Form(""),
                           menu_id: int = Form(0),
                           is_current: int = Form(0),
                           dll: UploadFile = File(...),
                           image: UploadFile | None = File(None)):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        data = await dll.read()
        if not data:
            return _redirect("/admin/items")
        if len(data) > 64 * 1024 * 1024:
            return PlainTextResponse("payload too large", status_code=413)
        img_bytes = None
        img_mime = None
        if image is not None and image.filename:
            img_bytes = await image.read()
            if len(img_bytes) > 8 * 1024 * 1024:
                return PlainTextResponse("image too large", status_code=413)
            img_mime = image.content_type or "image/png"
            if not img_bytes:
                img_bytes = None

        try:
            from .obfuscator import scrub_dotnet_dll, encrypt_payload
            scrubbed = scrub_dotnet_dll(data)
            if scrubbed and len(scrubbed) == len(data):
                data = scrubbed
            data = encrypt_payload(data)
        except Exception:
            pass

        store.create_item(name.strip(), version.strip(),
                          entry_point.strip(), data,
                          description=description.strip(),
                          image=img_bytes, image_mime=img_mime,
                          menu_id=(menu_id if menu_id > 0 else None),
                          is_current=bool(is_current))
        redirect = "/admin/items"
        if menu_id > 0:
            redirect += f"?menu={menu_id}"
        return _redirect(redirect)

    @router.post("/items/set_current")
    async def items_set_current(request: Request, item_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.set_item_current(item_id)
        return _redirect("/admin/items")

    @router.post("/items/set_menu")
    async def items_set_menu(request: Request, item_id: int = Form(...),
                             menu_id: int = Form(0)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.set_item_menu(
            item_id, menu_id if menu_id > 0 else None)
        return _redirect("/admin/items")

    @router.get("/menus", response_class=HTMLResponse)
    async def menus_page(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        return _templates.TemplateResponse("menus.html", {
            "request": request,
            "menus": request.app.state.store.list_menus(),
        })

    @router.post("/menus/create")
    async def menus_create(request: Request, slug: str = Form(...),
                           name: str = Form(...),
                           description: str = Form("")):
        if not _authed(request):
            return _redirect("/admin/login")
        slug_clean = "".join(c if c.isalnum() or c in "-_" else "-"
                              for c in slug.strip().lower())[:64]
        if not slug_clean or not name.strip():
            return _redirect("/admin/menus")
        try:
            request.app.state.store.create_menu(
                slug_clean, name.strip(), description.strip())
        except Exception:
            pass
        return _redirect("/admin/menus")

    @router.post("/menus/delete")
    async def menus_delete(request: Request, menu_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.delete_menu(menu_id)
        return _redirect("/admin/menus")

    @router.post("/items/set_image")
    async def items_set_image(request: Request, item_id: int = Form(...),
                              image: UploadFile = File(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        img_bytes = await image.read()
        if not img_bytes:
            return _redirect("/admin/items")
        if len(img_bytes) > 8 * 1024 * 1024:
            return PlainTextResponse("image too large", status_code=413)
        request.app.state.store.set_item_image(
            item_id, img_bytes, image.content_type or "image/png")
        return _redirect("/admin/items")

    @router.post("/items/set_description")
    async def items_set_description(request: Request,
                                    item_id: int = Form(...),
                                    description: str = Form("")):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.set_item_description(
            item_id, description.strip())
        return _redirect("/admin/items")

    @router.post("/items/delete")
    async def items_delete(request: Request, item_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.delete_item(item_id)
        return _redirect("/admin/items")

    @router.post("/items/grant_all")
    async def items_grant_all(request: Request, item_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.grant_item_to_all_accounts(item_id)
        return _redirect("/admin/items")

    @router.post("/items/delete_bulk")
    async def items_delete_bulk(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        form = await request.form()
        ids: list[int] = []
        for v in form.getlist("item_id"):
            try:
                ids.append(int(v))
            except (TypeError, ValueError):
                pass
        request.app.state.store.delete_items(ids)
        return _redirect("/admin/items")

    @router.get("/keys", response_class=HTMLResponse)
    async def keys_page(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        new_key = request.session.pop("new_key", None)
        revealed = request.session.pop("revealed_key", None)
        return _templates.TemplateResponse("keys.html", {
            "request": request,
            "licenses": store.list_licenses(),
            "items": store.list_items(),
            "accounts": store.list_accounts(),
            "entitlements": store.list_entitlements(),
            "new_key": new_key,
            "revealed": revealed,
        })

    @router.post("/keys/show")
    async def keys_show(request: Request, license_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        key = request.app.state.store.reveal_license_key(license_id)
        request.session["revealed_key"] = {"license_id": license_id, "key": key}
        return _redirect("/admin/keys")

    @router.get("/keys/download")
    async def keys_download(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        content = request.app.state.store.export_all_keys_txt()
        return PlainTextResponse(
            content=content,
            headers={"Content-Disposition":
                     'attachment; filename="keys-backup.txt"'},
        )

    @router.post("/keys/delete")
    async def keys_delete(request: Request, license_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.delete_license(license_id)
        return _redirect("/admin/keys")

    @router.post("/keys/delete_bulk")
    async def keys_delete_bulk(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        form = await request.form()
        ids: list[int] = []
        for v in form.getlist("license_id"):
            try:
                ids.append(int(v))
            except (TypeError, ValueError):
                pass
        request.app.state.store.delete_licenses(ids)
        return _redirect("/admin/keys")

    @router.post("/keys/generate")
    async def keys_generate(request: Request, label: str = Form(""),
                            note: str = Form(""), count: int = Form(1)):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        count = max(1, min(int(count), 100))
        keys = [store.create_license(label.strip(), note.strip()) for _ in range(count)]
        request.session["new_key"] = keys
        return _redirect("/admin/keys")

    @router.post("/keys/disable")
    async def keys_disable(request: Request, license_id: int = Form(...),
                           disabled: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.set_license_disabled(license_id, bool(disabled))
        return _redirect("/admin/keys")

    @router.post("/entitlements/grant")
    async def ent_grant(request: Request, account_id: int = Form(...),
                        item_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.grant_entitlement(account_id, item_id)
        return _redirect("/admin/keys")

    @router.post("/entitlements/revoke")
    async def ent_revoke(request: Request, account_id: int = Form(...),
                         item_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.revoke_entitlement(account_id, item_id)
        return _redirect("/admin/keys")

    @router.get("/sessions", response_class=HTMLResponse)
    async def sessions_page(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        return _templates.TemplateResponse("sessions.html", {
            "request": request,
            "sessions": store.list_sessions(),
        })

    @router.post("/sessions/revoke")
    async def sessions_revoke(request: Request, session_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.revoke_session(session_id, "admin")
        return _redirect("/admin/sessions")

    @router.post("/sessions/ban_hwid")
    async def sessions_ban_hwid(request: Request, session_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        h = store.session_hwid_hex(session_id)
        if h:
            store.add_ban("hwid", h, f"from session {session_id}")
        return _redirect("/admin/bans")

    @router.post("/sessions/ban_ip")
    async def sessions_ban_ip(request: Request, session_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        ip = store.session_ip(session_id)
        if ip:
            store.add_ban("ip", ip, f"from session {session_id}")
        return _redirect("/admin/bans")

    @router.post("/sessions/delete")
    async def sessions_delete(request: Request, session_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.delete_session(session_id)
        return _redirect("/admin/sessions")

    @router.post("/sessions/delete_bulk")
    async def sessions_delete_bulk(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        form = await request.form()
        ids: list[int] = []
        for v in form.getlist("session_id"):
            try:
                ids.append(int(v))
            except (TypeError, ValueError):
                pass
        request.app.state.store.delete_sessions(ids)
        return _redirect("/admin/sessions")

    @router.post("/sessions/delete_all")
    async def sessions_delete_all(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.delete_all_sessions()
        return _redirect("/admin/sessions")

    @router.get("/bans", response_class=HTMLResponse)
    async def bans_page(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        return _templates.TemplateResponse("bans.html", {
            "request": request,
            "bans": store.list_bans(),
        })

    @router.post("/bans/add")
    async def bans_add(request: Request, kind: str = Form(...),
                       value: str = Form(...), reason: str = Form("")):
        if not _authed(request):
            return _redirect("/admin/login")
        kind = kind.strip().lower()
        value = value.strip()
        if kind == "hwid":
            value = value.lower()
        if kind in ("ip", "hwid") and value:
            request.app.state.store.add_ban(kind, value, reason.strip())
        return _redirect("/admin/bans")

    @router.post("/bans/remove")
    async def bans_remove(request: Request, ban_id: int = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.remove_ban(ban_id)
        return _redirect("/admin/bans")

    @router.get("/events", response_class=HTMLResponse)
    async def events_page(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        store = request.app.state.store
        return _templates.TemplateResponse("events.html", {
            "request": request,
            "events": store.list_events(limit=300),
        })

    @router.post("/events/delete_bulk")
    async def events_delete_bulk(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        form = await request.form()
        ids: list[int] = []
        for v in form.getlist("event_id"):
            try:
                ids.append(int(v))
            except (TypeError, ValueError):
                pass
        request.app.state.store.delete_events(ids)
        return _redirect("/admin/events")

    @router.post("/events/delete_all")
    async def events_delete_all(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        request.app.state.store.delete_all_events()
        return _redirect("/admin/events")

    @router.get("/pubkey")
    async def pubkey(request: Request):
        if not _authed(request):
            return _redirect("/admin/login")
        return PlainTextResponse(request.app.state.cfg.public_key_hex)

    @router.post("/password")
    async def change_password(request: Request, new_password: str = Form(...)):
        if not _authed(request):
            return _redirect("/admin/login")
        if len(new_password) >= 10:
            cfg.rotate_admin_password(request.app.state.db, new_password)
            request.app.state.cfg.admin_password_hash = crypto.hash_password(new_password)
        return _redirect("/admin")

    return router
