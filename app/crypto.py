"""
Cryptography helpers.

- ECDSA P-256 signing key used to sign every server response (the client holds
  only the public key, embedded in the loader).
- Encryption-at-rest for the private key (Fernet, keyed by an application
  secret stored next to the app).
- Admin password hashing (scrypt).

Nothing here is secret-by-obscurity: the private key is the only thing that
must stay on the server, and it is what makes a forged response impossible.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

CURVE = ec.SECP256R1()

# ---------------------------------------------------------------------------
# Application secret + private-key encryption at rest
# ---------------------------------------------------------------------------


def load_or_create_app_secret(path: str) -> bytes:
    """A 32-byte Fernet key kept beside the app. In production this belongs in a
    real secret store (see README / design doc section 16)."""
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read()
    key = Fernet.generate_key()
    with open(path, "wb") as fh:
        fh.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows: best-effort
    return key


def generate_signing_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def encrypt_private_key(priv: ec.EllipticCurvePrivateKey, app_secret: bytes) -> bytes:
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return Fernet(app_secret).encrypt(pem)


def decrypt_private_key(blob: bytes, app_secret: bytes) -> ec.EllipticCurvePrivateKey:
    pem = Fernet(app_secret).decrypt(blob)
    return serialization.load_pem_private_key(pem, password=None)


# ---------------------------------------------------------------------------
# Public key export (what gets embedded in the loader)
# ---------------------------------------------------------------------------


def public_key_xy(priv: ec.EllipticCurvePrivateKey) -> bytes:
    """Raw X||Y, 64 bytes — the form the C# client embeds."""
    nums = priv.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def public_key_xy_hex(priv: ec.EllipticCurvePrivateKey) -> str:
    return public_key_xy(priv).hex()


# ---------------------------------------------------------------------------
# Signing (raw r||s, 64 bytes — matches .NET ECDsa)
# ---------------------------------------------------------------------------


def sign(priv: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    der = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(pub_xy: bytes, message: bytes, sig64: bytes) -> bool:
    """Only used by tests / a loopback harness; the real verifier is the C#
    client. Mirrors its logic so tests prove cross-compatibility."""
    x = int.from_bytes(pub_xy[:32], "big")
    y = int.from_bytes(pub_xy[32:64], "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key()
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:64], "big")
    der = encode_dss_signature(r, s)
    try:
        pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# Admin password hashing (scrypt, stdlib)
# ---------------------------------------------------------------------------

_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
# OpenSSL's default maxmem (32 MB) is just under what N=2^15,r=8 needs (~34 MB),
# so set it explicitly with headroom.
_SCRYPT_MAXMEM = 128 * _SCRYPT_N * _SCRYPT_R * _SCRYPT_P * 2


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
        p=_SCRYPT_P, maxmem=_SCRYPT_MAXMEM,
    )
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
            p=_SCRYPT_P, maxmem=_SCRYPT_MAXMEM,
        )
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Random generators
# ---------------------------------------------------------------------------


def random_id() -> bytes:
    return secrets.token_bytes(16)


def random_secret() -> bytes:
    return secrets.token_bytes(32)


def random_license_key() -> str:
    """Human-ish, high-entropy. 5 groups of 5 Crockford base32 chars = ~128 bits."""
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(5)]
    return "-".join(groups)


def random_username() -> str:
    return "admin_" + secrets.token_hex(4)


def random_password(n: int = 20) -> str:
    alphabet = (
        "abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#%^*-_=+"
    )
    return "".join(secrets.choice(alphabet) for _ in range(n))
