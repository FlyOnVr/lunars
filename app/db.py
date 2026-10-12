from __future__ import annotations

import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label        TEXT,
    flagged      INTEGER NOT NULL DEFAULT 0,
    flag_reason  TEXT,
    created      REAL NOT NULL
);

-- licenses: SHA-256(key) for lookup + an encrypted-at-rest copy of the key
-- so the dashboard can reveal it. The encryption key lives in secret.key.
CREATE TABLE IF NOT EXISTS licenses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash    BLOB NOT NULL UNIQUE,
    key_enc     BLOB,                 -- Fernet-encrypted plaintext key
    account_id  INTEGER NOT NULL,
    disabled    INTEGER NOT NULL DEFAULT 0,
    hwid_hash   BLOB,                 -- bound on first login
    note        TEXT,
    created     REAL NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

-- what each account is allowed to receive. Written by the dashboard (and, in
-- production, by a payment webhook) — never by the client.
CREATE TABLE IF NOT EXISTS entitlements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL,
    item_id     INTEGER NOT NULL,
    source      TEXT,                 -- e.g. payment txn id
    created     REAL NOT NULL,
    UNIQUE (account_id, item_id)
);

-- the paid code itself (the payload the server delivers after a verified check)
CREATE TABLE IF NOT EXISTS items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     TEXT,
    entry_point TEXT,                 -- type/method the loader invokes
    payload     BLOB NOT NULL,        -- the (obfuscated) assembly/bundle bytes
    created     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   INTEGER NOT NULL,
    hwid_hash    BLOB,
    ip           TEXT,
    created      REAL NOT NULL,
    last_seen    REAL NOT NULL,
    alive        INTEGER NOT NULL DEFAULT 1,
    revoke_reason TEXT
);

CREATE TABLE IF NOT EXISTS tokens (
    id           BLOB PRIMARY KEY,    -- 16-byte random id
    secret_hash  BLOB NOT NULL,       -- SHA-256(secret)
    session_id   INTEGER NOT NULL,
    account_id   INTEGER NOT NULL,
    expires_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS spent (
    id          BLOB PRIMARY KEY,
    session_id  INTEGER NOT NULL,
    account_id  INTEGER NOT NULL,
    expires_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS bans (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    kind     TEXT NOT NULL,           -- 'ip' | 'hwid'
    value    TEXT NOT NULL,           -- ip string, or hwid_hash hex
    reason   TEXT,
    created  REAL NOT NULL,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS delivery_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    account_id  INTEGER NOT NULL,
    item_id     INTEGER NOT NULL,
    stamp       TEXT,
    created     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    session_id  INTEGER,
    account_id  INTEGER,
    ip          TEXT,
    detail      TEXT,
    created     REAL NOT NULL
);

-- single-row app config: encrypted signing key, admin creds, public key hex
CREATE TABLE IF NOT EXISTS app_config (
    k  TEXT PRIMARY KEY,
    v  BLOB
);

CREATE INDEX IF NOT EXISTS ix_tokens_session  ON tokens(session_id);
CREATE INDEX IF NOT EXISTS ix_sessions_account ON sessions(account_id);
CREATE INDEX IF NOT EXISTS ix_events_created  ON events(created);
"""

class Database:
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()
        with self.lock:
            self._conn.executescript(SCHEMA)
            self._apply_migrations()

    def _apply_migrations(self):
        cols = {r[1] for r in self._conn.execute(
            "PRAGMA table_info(licenses)").fetchall()}
        if "key_enc" not in cols:
            self._conn.execute("ALTER TABLE licenses ADD COLUMN key_enc BLOB")

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def close(self):
        self._conn.close()
