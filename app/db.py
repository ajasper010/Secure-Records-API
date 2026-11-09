"""Storage layer. Every query is parameterised (`?` placeholders) - no string-built SQL."""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id         TEXT PRIMARY KEY,
    owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_owner ON records(owner_id);
CREATE TABLE IF NOT EXISTS login_attempts (   -- per ACCOUNT, not per IP
    username     TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL,
    locked_until REAL NOT NULL DEFAULT 0,
    last_attempt REAL NOT NULL
);
"""


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE"], isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.executescript(SCHEMA)
    conn.close()


# ---- users ----
def create_user(username, password_hash, role, ts):
    cur = get_db().execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, password_hash, role, ts),
    )
    return cur.lastrowid


def get_user_by_username(username):
    return get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


# ---- sessions ----
def create_session(token_hash, user_id, expires_at, ts):
    get_db().execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (token_hash, user_id, expires_at, ts),
    )


def get_user_for_session(token_hash, ts):
    # Role is read from the users table on EVERY request, never from the token.
    return get_db().execute(
        "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?",
        (token_hash, ts),
    ).fetchone()


def delete_session(token_hash):
    get_db().execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def purge_expired_sessions(ts):
    get_db().execute("DELETE FROM sessions WHERE expires_at <= ?", (ts,))


# ---- records ----
def create_record(record_id, owner_id, title, body, ts):
    get_db().execute(
        "INSERT INTO records (id, owner_id, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (record_id, owner_id, title, body, ts),
    )


def get_record(record_id):
    return get_db().execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
