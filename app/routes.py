"""HTTP layer only: parse -> validate -> call auth/db -> respond."""
import sqlite3
import uuid

from flask import Blueprint, current_app, g, jsonify

from . import auth, db, security, validation as v

bp = Blueprint("api", __name__)


@bp.post("/register")
def register():
    data = v.parse_body({"username", "password"})  # 'role' etc. -> 403 inside parse_body
    username = v.username_field(data)
    password = v.password_field(data, min_len=8)
    pw_hash = security.hash_password(password, current_app.config["PASSWORD_PEPPER"])
    try:
        # Role is hard-coded server-side: self-registration can only ever create a 'user'.
        user_id = db.create_user(username, pw_hash, "user", security.now())
    except sqlite3.IntegrityError:
        return jsonify(error="username already taken"), 409
    return jsonify(id=user_id, username=username, role="user"), 201


@bp.post("/login")
def login():
    cfg = current_app.config
    data = v.parse_body({"username", "password"})
    username = v.username_field(data)
    password = v.password_field(data, min_len=1)

    retry_after = auth.register_login_attempt(username)
    if retry_after:
        resp = jsonify(error="too many failed attempts; try again later")
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    user = db.get_user_by_username(username)
    stored = user["password_hash"] if user else security.dummy_hash(cfg["PASSWORD_PEPPER"])
    ok = security.verify_password(password, stored, cfg["PASSWORD_PEPPER"])  # runs even if no user
    if not (user and ok):
        return jsonify(error="invalid credentials"), 401  # same answer for bad user / bad password

    auth.clear_login_attempts(username)
    ts = security.now()
    db.purge_expired_sessions(ts)
    token = security.new_session_token()
    db.create_session(security.token_digest(token), user["id"], ts + cfg["SESSION_TTL_SECONDS"], ts)
    return jsonify(token=token, token_type="Bearer", expires_in=cfg["SESSION_TTL_SECONDS"]), 200


@bp.post("/logout")
@auth.login_required
def logout():
    db.delete_session(security.token_digest(g.token))
    return "", 204


@bp.post("/records")
@auth.login_required
def create_record():
    data = v.parse_body({"title", "body"})
    title, body = v.title_field(data), v.body_field(data)
    record_id = str(uuid.uuid4())  # unguessable id (defence in depth; the ACL check is the real control)
    db.create_record(record_id, g.user["id"], title, body, security.now())  # owner = session user, never client input
    return jsonify(id=record_id), 201


@bp.get("/records/<record_id>")
@auth.login_required
def read_record(record_id):
    rid = v.record_id_or_none(record_id)
    record = db.get_record(rid) if rid else None
    # Missing and "not yours" give the SAME 404, so ids can't be probed for existence.
    if record is None or not auth.can_read_record(g.user, record):
        return jsonify(error="record not found"), 404
    return jsonify(
        id=record["id"], title=record["title"], body=record["body"],
        owner_id=record["owner_id"], created_at=record["created_at"],
    ), 200
