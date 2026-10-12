"""
Wire format + the server's decision logic, as pure-ish functions over bytes.

This is the heart of the design doc (sections 5, 7, 8, 9). It depends only on a
`Store` interface, so it can be driven directly in tests with an in-memory store
and no network.

Wire format
-----------
Login request    : 0x01 | cn(16) | hwid_hash(32) | license_key (UTF-8, rest)
Exchange request : 0x02 | id(16) | secret(32) | cn(16) | item_id(4 BE)   = 69 bytes
Response (both)  : next_id(16) | next_secret(32) | payload(n) | signature(64)
Signed bytes     : VER(1) | CTX(1) | req_id(16) | cn(16) | next_id(16)
                   | next_secret(32) | payload
                   (req_id is 16 zero bytes for login)
Failure          : empty bytes (b""). No error codes leak which check failed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from . import crypto

PROTO_VERSION = 0x01
CTX_LOGIN = 0x01
CTX_EXCHANGE = 0x02

MSG_LOGIN = 0x01
MSG_EXCHANGE = 0x02

ZERO_ID = b"\x00" * 16
EXCHANGE_LEN = 1 + 16 + 32 + 16 + 4  # 69
HEARTBEAT_ITEM = 0

TOKEN_TTL_SECONDS = 60
SPENT_TTL_SECONDS = 600       # ~10 min
RETRY_WINDOW_SECONDS = 10


# ---------------------------------------------------------------------------
# Store interface (implemented by store.SqliteStore and tests' InMemoryStore)
# ---------------------------------------------------------------------------


@dataclass
class TokenRow:
    id: bytes
    secret_hash: bytes
    session_id: int
    account_id: int
    expires_at: float


@dataclass
class ConsumeResult:
    found: bool
    token: Optional[TokenRow] = None


class Store(Protocol):
    def now(self) -> float: ...

    # bans
    def is_ip_banned(self, ip: str) -> bool: ...
    def is_hwid_banned(self, hwid_hash: bytes) -> bool: ...

    # login
    def find_license_by_hash(self, key_hash: bytes): ...
    def hwid_check_and_bind(self, license_id: int, hwid_hash: bytes) -> bool: ...
    def revoke_account_sessions(self, account_id: int, reason: str) -> None: ...
    def create_session(self, account_id: int, hwid_hash: bytes, ip: str) -> int: ...

    # tokens
    def issue_token(self, session_id: int, account_id: int) -> tuple[bytes, bytes]: ...
    def consume_token(self, token_id: bytes) -> ConsumeResult: ...
    def session_alive(self, session_id: int) -> bool: ...
    def revoke_session(self, session_id: int, reason: str) -> None: ...
    def touch_session(self, session_id: int) -> None: ...
    def flag_account(self, account_id: int, reason: str) -> None: ...

    # spent / retry
    def spent_lookup(self, token_id: bytes): ...
    def record_spent(self, token_id: bytes, session_id: int) -> None: ...
    def retry_cache_get(self, token_id: bytes): ...
    def retry_cache_put(self, token_id: bytes, cn: bytes, response: bytes) -> None: ...

    # entitlement / payload
    def build_payload(self, account_id: int, item_id: int, session_id: int) -> bytes: ...

    # logging
    def log_event(self, kind: str, session_id: int, account_id: int, ip: str, detail: str) -> None: ...


# ---------------------------------------------------------------------------
# Signed-bytes construction
# ---------------------------------------------------------------------------


def _signed_bytes(ctx: int, req_id: bytes, cn: bytes, next_id: bytes,
                  next_secret: bytes, payload: bytes) -> bytes:
    return (bytes([PROTO_VERSION, ctx]) + req_id + cn + next_id + next_secret + payload)


def _build_response(priv, ctx: int, req_id: bytes, cn: bytes, next_id: bytes,
                    next_secret: bytes, payload: bytes) -> bytes:
    msg = _signed_bytes(ctx, req_id, cn, next_id, next_secret, payload)
    sig = crypto.sign(priv, msg)
    return next_id + next_secret + payload + sig


FAIL = b""  # empty response == failure, leaks nothing


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def handle_login(store: Store, priv, body: bytes, ip: str) -> bytes:
    if len(body) < 1 + 16 + 32 + 1:
        return FAIL
    if body[0] != MSG_LOGIN:
        return FAIL
    if store.is_ip_banned(ip):
        return FAIL

    cn = body[1:17]
    hwid_hash = body[17:49]
    license_key = body[49:].decode("utf-8", "ignore").strip()
    if not license_key:
        return FAIL

    if store.is_hwid_banned(hwid_hash):
        return FAIL

    lic = store.find_license_by_hash(crypto.sha256(license_key.encode("utf-8")))
    if lic is None or lic.disabled:
        return FAIL

    if not store.hwid_check_and_bind(lic.id, hwid_hash):
        # license bound to a different machine
        store.log_event("login_hwid_mismatch", 0, lic.account_id, ip, "")
        return FAIL

    # one active session per license: kill any prior session
    store.revoke_account_sessions(lic.account_id, "new_login")
    session_id = store.create_session(lic.account_id, hwid_hash, ip)

    next_id, next_secret = store.issue_token(session_id, lic.account_id)
    store.touch_session(session_id)
    store.log_event("login_ok", session_id, lic.account_id, ip, "")

    return _build_response(priv, CTX_LOGIN, ZERO_ID, cn, next_id, next_secret, b"")


# ---------------------------------------------------------------------------
# Exchange (purchase check or heartbeat)  —  decision order = design doc §8
# ---------------------------------------------------------------------------


def handle_exchange(store: Store, priv, body: bytes, ip: str) -> bytes:
    # 1. length check — cheapest
    if len(body) != EXCHANGE_LEN or body[0] != MSG_EXCHANGE:
        return FAIL
    if store.is_ip_banned(ip):
        return FAIL

    req_id = body[1:17]
    secret = body[17:49]
    cn = body[49:65]
    item_id = int.from_bytes(body[65:69], "big")

    # 2. spent lookup  (§9: retry vs reuse)
    spent = store.spent_lookup(req_id)
    if spent is not None:
        cached = store.retry_cache_get(req_id)
        if (cached is not None and cached.cn == cn
                and (store.now() - cached.ts) <= RETRY_WINDOW_SECONDS):
            # idempotent retry: resend identical cached response
            return cached.response
        # anything else touching a spent id == reuse
        store.revoke_session(spent.session_id, "reuse")
        store.flag_account(spent.account_id, "reuse")
        store.log_event("reuse", spent.session_id, spent.account_id, ip, req_id.hex())
        return FAIL

    # 3. consume by id, atomically — unknown id == reject
    res = store.consume_token(req_id)
    if not res.found:
        return FAIL
    tok = res.token

    # 4. expiry + session alive — reject WITHOUT revoking (likely idle player)
    if tok.expires_at < store.now() or not store.session_alive(tok.session_id):
        return FAIL

    # 5. hash compare, constant time — mismatch revokes the session
    if not crypto.constant_time_eq(crypto.sha256(secret), tok.secret_hash):
        store.revoke_session(tok.session_id, "bad_secret")
        store.log_event("bad_secret", tok.session_id, tok.account_id, ip, "")
        return FAIL

    # 6. entitlement lookup -> payload. On any error, still issue the next pair
    #    with an empty payload so the client never loses its pair.
    try:
        payload = b"" if item_id == HEARTBEAT_ITEM else store.build_payload(
            tok.account_id, item_id, tok.session_id)
    except Exception:
        payload = b""

    # 7. issue next pair
    next_id, next_secret = store.issue_token(tok.session_id, tok.account_id)
    store.touch_session(tok.session_id)

    # 8. sign (only expensive step, reached only after cheap checks pass)
    response = _build_response(priv, CTX_EXCHANGE, req_id, cn, next_id,
                               next_secret, payload)

    # 9. record spent + retry cache
    store.record_spent(req_id, tok.session_id)
    store.retry_cache_put(req_id, cn, response)

    # 10. return
    return response
