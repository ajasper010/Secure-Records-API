"""Session authentication, role checks and per-account login throttling (our own code)."""
import math
from functools import wraps

from flask import current_app, g, jsonify, request

from . import db, security


def _unauthorized():
    resp = jsonify(error="authentication required")
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = "Bearer"
    return resp


def _bearer_token():
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 256:
        return None
    return token.strip()


def login_required(view):
    """Session integrity: opaque token looked up (as a hash) server-side on EVERY request."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = _bearer_token()
        if token is None:
            return _unauthorized()
        user = db.get_user_for_session(security.token_digest(token), security.now())
        if user is None:  # unknown, revoked or expired
            return _unauthorized()
        g.user, g.token = user, token
        return view(*args, **kwargs)
    return wrapper


def register_login_attempt(username):
    """Atomically count an attempt against this ACCOUNT *before* the password is checked.

    Returns None if the attempt may proceed, or the seconds to wait if the account is locked.
    Counting first (inside a write transaction) means concurrent guesses cannot slip past the limit.
    Works for non-existent usernames too, so lockout behaviour does not reveal which accounts exist.
    """
    cfg, conn, ts = current_app.config, db.get_db(), security.now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        # housekeeping: drop stale, unlocked rows so the table cannot grow without bound
        conn.execute(
            "DELETE FROM login_attempts WHERE locked_until <= ? AND last_attempt < ?",
            (ts, ts - cfg["FAILURE_WINDOW_SECONDS"]),
        )
        row = conn.execute(
            "SELECT failures, locked_until, last_attempt FROM login_attempts WHERE username = ?",
            (username,),
        ).fetchone()
        retry_after, failures, locked_until = None, 0, 0.0
        if row:
            if row["locked_until"] > ts:
                conn.execute("COMMIT")
                return max(1, math.ceil(row["locked_until"] - ts))
            if ts - row["last_attempt"] < cfg["FAILURE_WINDOW_SECONDS"]:
                failures = row["failures"]
        if failures >= cfg["MAX_LOGIN_FAILURES"]:
            locked_until, failures = ts + cfg["LOCKOUT_SECONDS"], 0
            retry_after = cfg["LOCKOUT_SECONDS"]
        else:
            failures += 1
        conn.execute(
            "INSERT INTO login_attempts (username, failures, locked_until, last_attempt) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET "
            "failures = excluded.failures, locked_until = excluded.locked_until, "
            "last_attempt = excluded.last_attempt",
            (username, failures, locked_until, ts),
        )
        conn.execute("COMMIT")
        return retry_after
    except Exception:
        conn.execute("ROLLBACK")
        raise


def clear_login_attempts(username):
    db.get_db().execute("DELETE FROM login_attempts WHERE username = ?", (username,))


def can_read_record(user, record):
    """Object-level access control: owner or admin. Called on every record read."""
    return record["owner_id"] == user["id"] or user["role"] == "admin"
