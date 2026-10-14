from __future__ import annotations

import os
from dataclasses import dataclass

from . import crypto
from .db import Database

@dataclass
class AppConfig:
    priv_key: object
    public_key_hex: str
    admin_username: str
    admin_password_hash: str
    cookie_secret: str
    app_secret: bytes

def _get(db: Database, k: str):
    with db.lock:
        r = db.conn.execute("SELECT v FROM app_config WHERE k=?", (k,)).fetchone()
        return r["v"] if r else None

def _set(db: Database, k: str, v: bytes):
    with db.lock:
        db.conn.execute(
            "INSERT OR REPLACE INTO app_config(k,v) VALUES(?,?)", (k, v)
        )

def bootstrap(db: Database, data_dir: str) -> AppConfig:
    app_secret = crypto.load_or_create_app_secret(os.path.join(data_dir, "secret.key"))

    first_run = _get(db, "priv_key_enc") is None
    if first_run:
        priv = crypto.generate_signing_key()
        _set(db, "priv_key_enc", crypto.encrypt_private_key(priv, app_secret))
        _set(db, "public_key_hex", crypto.public_key_xy_hex(priv).encode())

        admin_user = crypto.random_username()
        admin_pass = crypto.random_password()
        _set(db, "admin_username", admin_user.encode())
        _set(db, "admin_password_hash", crypto.hash_password(admin_pass).encode())
        _set(db, "cookie_secret", crypto.random_password(48).encode())

        _write_first_run_file(data_dir, admin_user, admin_pass)
        _print_first_run(admin_user, admin_pass)

    priv = crypto.decrypt_private_key(_get(db, "priv_key_enc"), app_secret)
    return AppConfig(
        priv_key=priv,
        public_key_hex=_get(db, "public_key_hex").decode(),
        admin_username=_get(db, "admin_username").decode(),
        admin_password_hash=_get(db, "admin_password_hash").decode(),
        cookie_secret=_get(db, "cookie_secret").decode(),
        app_secret=app_secret,
    )

def rotate_admin_password(db: Database, new_password: str) -> None:
    _set(db, "admin_password_hash", crypto.hash_password(new_password).encode())

def _write_first_run_file(data_dir: str, user: str, pw: str) -> None:
    path = os.path.join(data_dir, "FIRST_RUN_CREDENTIALS.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            "Admin dashboard credentials (shown once).\n"
            "Save these somewhere safe, then DELETE this file.\n\n"
            f"username: {user}\n"
            f"password: {pw}\n"
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

def _print_first_run(user: str, pw: str) -> None:
    line = "=" * 60
    print(f"\n{line}\n FIRST RUN — admin dashboard credentials (shown once)\n{line}")
    print(f"  username: {user}")
    print(f"  password: {pw}")
    print(f"{line}\n  Saved to FIRST_RUN_CREDENTIALS.txt — delete it after saving.\n{line}\n")
