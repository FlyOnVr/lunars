from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from . import crypto
from .db import Database
from .protocol import (
    ConsumeResult,
    SPENT_TTL_SECONDS,
    TOKEN_TTL_SECONDS,
    TokenRow,
)

@dataclass
class License:
    id: int
    account_id: int
    disabled: bool
    hwid_hash: Optional[bytes]

@dataclass
class SpentRow:
    session_id: int
    account_id: int

@dataclass
class _RetryEntry:
    cn: bytes
    response: bytes
    ts: float

class SqliteStore:
    def __init__(self, db: Database, app_secret: bytes | None = None,
                 data_dir: str | None = None):
        self.db = db
        self._retry: dict[bytes, _RetryEntry] = {}
        self._fernet = Fernet(app_secret) if app_secret else None
        self._data_dir = data_dir

    def now(self) -> float:
        return time.time()

    def is_ip_banned(self, ip: str) -> bool:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT 1 FROM bans WHERE kind='ip' AND value=?", (ip,)
            ).fetchone()
            return r is not None

    def is_hwid_banned(self, hwid_hash: bytes) -> bool:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT 1 FROM bans WHERE kind='hwid' AND value=?", (hwid_hash.hex(),)
            ).fetchone()
            return r is not None

    def add_ban(self, kind: str, value: str, reason: str = "") -> None:
        with self.db.lock:
            self.db.conn.execute(
                "INSERT OR IGNORE INTO bans(kind,value,reason,created) VALUES(?,?,?,?)",
                (kind, value, reason, self.now()),
            )
        if kind == "ip":
            self._revoke_sessions_where("ip=?", (value,), "ip_ban")
        elif kind == "hwid":
            self._revoke_sessions_where("hwid_hash=?", (bytes.fromhex(value),), "hwid_ban")

    def remove_ban(self, ban_id: int) -> None:
        with self.db.lock:
            self.db.conn.execute("DELETE FROM bans WHERE id=?", (ban_id,))

    def list_bans(self):
        with self.db.lock:
            return self.db.conn.execute(
                "SELECT * FROM bans ORDER BY created DESC"
            ).fetchall()

    def find_license_by_hash(self, key_hash: bytes) -> Optional[License]:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT id, account_id, disabled, hwid_hash FROM licenses WHERE key_hash=?",
                (key_hash,),
            ).fetchone()
        if r is None:
            return None
        return License(r["id"], r["account_id"], bool(r["disabled"]), r["hwid_hash"])

    def hwid_check_and_bind(self, license_id: int, hwid_hash: bytes) -> bool:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT hwid_hash FROM licenses WHERE id=?", (license_id,)
            ).fetchone()
            if r is None:
                return False
            bound = r["hwid_hash"]
            if bound is None:
                self.db.conn.execute(
                    "UPDATE licenses SET hwid_hash=? WHERE id=?", (hwid_hash, license_id)
                )
                return True
            return crypto.constant_time_eq(bound, hwid_hash)

    def revoke_account_sessions(self, account_id: int, reason: str) -> None:
        self._revoke_sessions_where("account_id=? AND alive=1", (account_id,), reason)

    def _revoke_sessions_where(self, where: str, params, reason: str) -> None:
        with self.db.lock:
            self.db.conn.execute(
                f"UPDATE sessions SET alive=0, revoke_reason=? WHERE {where}",
                (reason, *params),
            )

    def create_session(self, account_id: int, hwid_hash: bytes, ip: str) -> int:
        with self.db.lock:
            cur = self.db.conn.execute(
                "INSERT INTO sessions(account_id,hwid_hash,ip,created,last_seen,alive) "
                "VALUES(?,?,?,?,?,1)",
                (account_id, hwid_hash, ip, self.now(), self.now()),
            )
            return cur.lastrowid

    def issue_token(self, session_id: int, account_id: int) -> tuple[bytes, bytes]:
        tid = crypto.random_id()
        secret = crypto.random_secret()
        with self.db.lock:
            self.db.conn.execute(
                "INSERT INTO tokens(id,secret_hash,session_id,account_id,expires_at) "
                "VALUES(?,?,?,?,?)",
                (tid, crypto.sha256(secret), session_id, account_id,
                 self.now() + TOKEN_TTL_SECONDS),
            )
        return tid, secret

    def consume_token(self, token_id: bytes) -> ConsumeResult:
        with self.db.lock:
            conn = self.db.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT secret_hash, session_id, account_id, expires_at "
                    "FROM tokens WHERE id=?", (token_id,)
                ).fetchone()
                if row is None:
                    conn.execute("COMMIT")
                    return ConsumeResult(found=False)
                cur = conn.execute("DELETE FROM tokens WHERE id=?", (token_id,))
                if cur.rowcount != 1:
                    conn.execute("COMMIT")
                    return ConsumeResult(found=False)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return ConsumeResult(
            found=True,
            token=TokenRow(
                id=token_id,
                secret_hash=row["secret_hash"],
                session_id=row["session_id"],
                account_id=row["account_id"],
                expires_at=row["expires_at"],
            ),
        )

    def session_alive(self, session_id: int) -> bool:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT alive FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
            return r is not None and bool(r["alive"])

    def revoke_session(self, session_id: int, reason: str) -> None:
        with self.db.lock:
            self.db.conn.execute(
                "UPDATE sessions SET alive=0, revoke_reason=? WHERE id=?",
                (reason, session_id),
            )

    def touch_session(self, session_id: int) -> None:
        with self.db.lock:
            self.db.conn.execute(
                "UPDATE sessions SET last_seen=? WHERE id=?", (self.now(), session_id)
            )

    def flag_account(self, account_id: int, reason: str) -> None:
        with self.db.lock:
            self.db.conn.execute(
                "UPDATE accounts SET flagged=1, flag_reason=? WHERE id=?",
                (reason, account_id),
            )

    def spent_lookup(self, token_id: bytes) -> Optional[SpentRow]:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT session_id, account_id, expires_at FROM spent WHERE id=?",
                (token_id,),
            ).fetchone()
        if r is None:
            return None
        if r["expires_at"] < self.now():
            return None
        return SpentRow(session_id=r["session_id"], account_id=r["account_id"])

    def record_spent(self, token_id: bytes, session_id: int) -> None:
        with self.db.lock:
            acc = self.db.conn.execute(
                "SELECT account_id FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
            account_id = acc["account_id"] if acc else 0
            self.db.conn.execute(
                "INSERT OR REPLACE INTO spent(id,session_id,account_id,expires_at) "
                "VALUES(?,?,?,?)",
                (token_id, session_id, account_id, self.now() + SPENT_TTL_SECONDS),
            )

    def retry_cache_get(self, token_id: bytes) -> Optional[_RetryEntry]:
        e = self._retry.get(token_id)
        if e is None:
            return None
        if self.now() - e.ts > SPENT_TTL_SECONDS:
            self._retry.pop(token_id, None)
            return None
        return e

    def retry_cache_put(self, token_id: bytes, cn: bytes, response: bytes) -> None:
        self._retry[token_id] = _RetryEntry(cn=cn, response=response, ts=self.now())

    def build_payload(self, account_id: int, item_id: int, session_id: int) -> bytes:
        with self.db.lock:
            ent = self.db.conn.execute(
                "SELECT 1 FROM entitlements WHERE account_id=? AND item_id=?",
                (account_id, item_id),
            ).fetchone()
            if ent is None:
                return b""
            item = self.db.conn.execute(
                "SELECT payload FROM items WHERE id=?", (item_id,)
            ).fetchone()
            if item is None:
                return b""
            payload = item["payload"]
            self.db.conn.execute(
                "INSERT INTO delivery_log(session_id,account_id,item_id,stamp,created) "
                "VALUES(?,?,?,?,?)",
                (session_id, account_id, item_id, f"s{session_id}", self.now()),
            )
        return bytes(payload)

    def log_event(self, kind: str, session_id: int, account_id: int, ip: str,
                  detail: str) -> None:
        with self.db.lock:
            self.db.conn.execute(
                "INSERT INTO events(kind,session_id,account_id,ip,detail,created) "
                "VALUES(?,?,?,?,?,?)",
                (kind, session_id or None, account_id or None, ip, detail, self.now()),
            )

    def create_account(self, label: str) -> int:
        with self.db.lock:
            cur = self.db.conn.execute(
                "INSERT INTO accounts(label,created) VALUES(?,?)", (label, self.now())
            )
            return cur.lastrowid

    def create_license(self, account_label: str, note: str = "") -> str:
        key = crypto.random_license_key()
        account_id = self.create_account(account_label or "customer")
        key_enc = self._fernet.encrypt(key.encode("utf-8")) if self._fernet else None
        with self.db.lock:
            self.db.conn.execute(
                "INSERT INTO licenses(key_hash,key_enc,account_id,note,created) "
                "VALUES(?,?,?,?,?)",
                (crypto.sha256(key.encode("utf-8")), key_enc,
                 account_id, note, self.now()),
            )
        self._grant_latest_item_to_account(account_id)
        self._append_key_to_backup_file(key, account_label or "customer", note)
        return key

    def _append_key_to_backup_file(self, key: str, label: str, note: str) -> None:
        if not self._data_dir:
            return
        path = os.path.join(self._data_dir, "keys.txt")
        try:
            ts = time.strftime("%Y-%m-%d %H:%M:%S",
                               time.localtime(self.now()))
            line = f"{ts}  {key}  label={label}"
            if note:
                line += f"  note={note}"
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def export_all_keys_txt(self) -> str:
        header = [
            "# License keys — full dump from database",
            "# generated " + time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                            time.gmtime(self.now())),
            "",
        ]
        with self.db.lock:
            rows = self.db.conn.execute(
                "SELECT l.key_enc, l.note, l.created, l.disabled, a.label "
                "FROM licenses l JOIN accounts a ON a.id=l.account_id "
                "ORDER BY l.created ASC"
            ).fetchall()
        lines = list(header)
        for r in rows:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created"]))
            key = "(no stored key)"
            if r["key_enc"] and self._fernet:
                try:
                    key = self._fernet.decrypt(r["key_enc"]).decode("utf-8")
                except InvalidToken:
                    key = "(decrypt failed)"
            tag = " [DISABLED]" if r["disabled"] else ""
            line = f"{ts}  {key}  label={r['label']}{tag}"
            if r["note"]:
                line += f"  note={r['note']}"
            lines.append(line)
        return "\n".join(lines) + "\n"

    def _grant_latest_item_to_account(self, account_id: int) -> bool:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT id FROM items ORDER BY created DESC LIMIT 1"
            ).fetchone()
            if r is None:
                return False
            self.db.conn.execute(
                "INSERT OR IGNORE INTO entitlements"
                "(account_id,item_id,source,created) VALUES(?,?,?,?)",
                (account_id, r["id"], "auto_latest_on_key_create", self.now()),
            )
            return True

    def grant_item_to_all_accounts(self, item_id: int) -> int:
        with self.db.lock:
            account_ids = [r["id"] for r in self.db.conn.execute(
                "SELECT id FROM accounts").fetchall()]
            added = 0
            for aid in account_ids:
                cur = self.db.conn.execute(
                    "INSERT OR IGNORE INTO entitlements"
                    "(account_id,item_id,source,created) VALUES(?,?,?,?)",
                    (aid, item_id, "auto_grant_all", self.now()),
                )
                if cur.rowcount > 0:
                    added += 1
            return added

    def reveal_license_key(self, license_id: int) -> Optional[str]:
        if not self._fernet:
            return None
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT key_enc FROM licenses WHERE id=?", (license_id,)
            ).fetchone()
        if r is None or r["key_enc"] is None:
            return None
        try:
            return self._fernet.decrypt(r["key_enc"]).decode("utf-8")
        except InvalidToken:
            return None

    def delete_license(self, license_id: int) -> None:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT account_id FROM licenses WHERE id=?", (license_id,)
            ).fetchone()
            if r is None:
                return
            account_id = r["account_id"]
            self.db.conn.execute(
                "UPDATE sessions SET alive=0, revoke_reason='license_deleted' "
                "WHERE account_id=? AND alive=1",
                (account_id,),
            )
            self.db.conn.execute(
                "DELETE FROM entitlements WHERE account_id=?", (account_id,)
            )
            self.db.conn.execute(
                "DELETE FROM tokens WHERE account_id=?", (account_id,)
            )
            self.db.conn.execute("DELETE FROM licenses WHERE id=?", (license_id,))
            other = self.db.conn.execute(
                "SELECT 1 FROM licenses WHERE account_id=? LIMIT 1", (account_id,)
            ).fetchone()
            if other is None:
                self.db.conn.execute(
                    "DELETE FROM accounts WHERE id=?", (account_id,)
                )

    def delete_licenses(self, license_ids: list[int]) -> int:
        count = 0
        for lid in license_ids:
            with self.db.lock:
                r = self.db.conn.execute(
                    "SELECT 1 FROM licenses WHERE id=?", (lid,)
                ).fetchone()
            if r is None:
                continue
            self.delete_license(lid)
            count += 1
        return count

    def set_license_disabled(self, license_id: int, disabled: bool) -> None:
        with self.db.lock:
            self.db.conn.execute(
                "UPDATE licenses SET disabled=? WHERE id=?",
                (1 if disabled else 0, license_id),
            )

    def list_licenses(self):
        with self.db.lock:
            return self.db.conn.execute(
                "SELECT l.id, l.account_id, l.disabled, l.hwid_hash, l.note, "
                "l.created, (l.key_enc IS NOT NULL) AS has_key_enc, "
                "a.label FROM licenses l JOIN accounts a ON a.id=l.account_id "
                "ORDER BY l.created DESC"
            ).fetchall()

    def create_item(self, name: str, version: str, entry_point: str,
                    payload: bytes) -> int:
        with self.db.lock:
            cur = self.db.conn.execute(
                "INSERT INTO items(name,version,entry_point,payload,created) "
                "VALUES(?,?,?,?,?)",
                (name, version, entry_point, payload, self.now()),
            )
            item_id = cur.lastrowid
        self.grant_item_to_all_accounts(item_id)
        return item_id

    def list_items(self):
        with self.db.lock:
            return self.db.conn.execute(
                "SELECT id,name,version,entry_point,length(payload) AS size,created "
                "FROM items ORDER BY created DESC"
            ).fetchall()

    def delete_item(self, item_id: int) -> None:
        with self.db.lock:
            self.db.conn.execute(
                "DELETE FROM entitlements WHERE item_id=?", (item_id,)
            )
            self.db.conn.execute(
                "DELETE FROM delivery_log WHERE item_id=?", (item_id,)
            )
            self.db.conn.execute("DELETE FROM items WHERE id=?", (item_id,))

    def delete_items(self, item_ids: list[int]) -> int:
        count = 0
        for iid in item_ids:
            with self.db.lock:
                r = self.db.conn.execute(
                    "SELECT 1 FROM items WHERE id=?", (iid,)
                ).fetchone()
            if r is None:
                continue
            self.delete_item(iid)
            count += 1
        return count

    def grant_entitlement(self, account_id: int, item_id: int, source: str = "dashboard"):
        with self.db.lock:
            self.db.conn.execute(
                "INSERT OR IGNORE INTO entitlements(account_id,item_id,source,created) "
                "VALUES(?,?,?,?)",
                (account_id, item_id, source, self.now()),
            )

    def revoke_entitlement(self, account_id: int, item_id: int):
        with self.db.lock:
            self.db.conn.execute(
                "DELETE FROM entitlements WHERE account_id=? AND item_id=?",
                (account_id, item_id),
            )

    def list_entitlements(self):
        with self.db.lock:
            return self.db.conn.execute(
                "SELECT e.account_id, e.item_id, e.source, e.created, "
                "a.label, i.name AS item_name "
                "FROM entitlements e JOIN accounts a ON a.id=e.account_id "
                "JOIN items i ON i.id=e.item_id ORDER BY e.created DESC"
            ).fetchall()

    def list_sessions(self, limit: int = 100):
        with self.db.lock:
            return self.db.conn.execute(
                "SELECT s.*, a.label FROM sessions s JOIN accounts a ON a.id=s.account_id "
                "ORDER BY s.last_seen DESC LIMIT ?", (limit,)
            ).fetchall()

    def delete_session(self, session_id: int) -> None:
        with self.db.lock:
            self.db.conn.execute(
                "DELETE FROM tokens WHERE session_id=?", (session_id,)
            )
            self.db.conn.execute(
                "DELETE FROM sessions WHERE id=?", (session_id,)
            )

    def delete_sessions(self, session_ids: list[int]) -> int:
        count = 0
        for sid in session_ids:
            with self.db.lock:
                r = self.db.conn.execute(
                    "SELECT 1 FROM sessions WHERE id=?", (sid,)
                ).fetchone()
            if r is None:
                continue
            self.delete_session(sid)
            count += 1
        return count

    def delete_all_sessions(self) -> int:
        with self.db.lock:
            n = self.db.conn.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone()[0]
            self.db.conn.execute("DELETE FROM tokens")
            self.db.conn.execute("DELETE FROM sessions")
        return int(n)

    def list_accounts(self):
        with self.db.lock:
            return self.db.conn.execute(
                "SELECT * FROM accounts ORDER BY created DESC"
            ).fetchall()

    def list_events(self, limit: int = 200):
        with self.db.lock:
            return self.db.conn.execute(
                "SELECT * FROM events ORDER BY created DESC LIMIT ?", (limit,)
            ).fetchall()

    def delete_events(self, event_ids: list[int]) -> int:
        if not event_ids:
            return 0
        placeholders = ",".join("?" for _ in event_ids)
        with self.db.lock:
            cur = self.db.conn.execute(
                f"DELETE FROM events WHERE id IN ({placeholders})",
                event_ids,
            )
            return cur.rowcount

    def delete_all_events(self) -> int:
        with self.db.lock:
            n = self.db.conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]
            self.db.conn.execute("DELETE FROM events")
        return int(n)

    def session_hwid_hex(self, session_id: int) -> Optional[str]:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT hwid_hash FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
        if r is None or r["hwid_hash"] is None:
            return None
        return r["hwid_hash"].hex()

    def session_ip(self, session_id: int) -> Optional[str]:
        with self.db.lock:
            r = self.db.conn.execute(
                "SELECT ip FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
        return r["ip"] if r else None

    def counts(self) -> dict:
        with self.db.lock:
            c = self.db.conn
            def one(q):
                return c.execute(q).fetchone()[0]
            return {
                "licenses": one("SELECT COUNT(*) FROM licenses"),
                "items": one("SELECT COUNT(*) FROM items"),
                "sessions_alive": one("SELECT COUNT(*) FROM sessions WHERE alive=1"),
                "bans": one("SELECT COUNT(*) FROM bans"),
                "reuse_events": one("SELECT COUNT(*) FROM events WHERE kind='reuse'"),
            }

    def sweep(self) -> None:
        now = self.now()
        with self.db.lock:
            self.db.conn.execute("DELETE FROM tokens WHERE expires_at < ?", (now,))
            self.db.conn.execute("DELETE FROM spent WHERE expires_at < ?", (now,))
        for tid in [k for k, e in self._retry.items()
                    if now - e.ts > SPENT_TTL_SECONDS]:
            self._retry.pop(tid, None)
