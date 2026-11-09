"""Crypto primitives: password hashing and session tokens. No Flask, no DB."""
import base64
import hashlib
import hmac
import secrets
import time

# scrypt parameters (memory-hard: ~16 MiB per hash). Stored in each hash so they can be raised later.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
SALT_BYTES = 16


def now():
    return time.time()


def _prehash(password: str, pepper: str) -> bytes:
    # HMAC with a server-side pepper (kept in env, NOT in the DB). A leaked user table alone
    # is then useless for offline cracking. Also normalises input length for scrypt.
    return hmac.new(pepper.encode(), password.encode("utf-8"), hashlib.sha256).digest()


def _scrypt(pre: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(pre, salt=salt, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024)


def hash_password(password: str, pepper: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)  # unique per user
    digest = _scrypt(_prehash(password, pepper), salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    b64 = lambda b: base64.b64encode(b).decode()
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str, pepper: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
        actual = _scrypt(_prehash(password, pepper), salt, int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)  # constant-time compare


_DUMMY = None


def dummy_hash(pepper: str) -> str:
    """Verified against when the username does not exist, so response time doesn't reveal it."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("dummy-password-for-timing", pepper)
    return _DUMMY


def new_session_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits from the OS CSPRNG


def token_digest(token: str) -> str:
    # Only the SHA-256 of the token is stored: a DB leak does not leak usable sessions.
    # (A fast hash is fine here because the token is 256-bit random, not a human password.)
    return hashlib.sha256(token.encode()).hexdigest()
