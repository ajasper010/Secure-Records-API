# Secure Records API (Nestack take-home)

Multi-tenant records API in **Python / Flask + SQLite**. Authentication, sessions, access control and
login throttling are **hand-written** (no auth library). Only Flask (HTTP framework) is a dependency;
crypto uses the standard library (`hashlib.scrypt`, `hmac`, `secrets`).

## Run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then set PASSWORD_PEPPER (see file for how to generate)
python run.py             # http://127.0.0.1:5000
python -m unittest discover -s tests -t . -v     # 32 tests
```

Create an admin (the ONLY way to get one - it is not reachable over HTTP):
```bash
python manage.py create-admin alice        # prompts for password (min 12 chars)
```

## API

| Method | Path | Body | Success | Failures |
|---|---|---|---|---|
| POST | `/register` | `{username, password}` | 201 (role is always `user`) | 400 invalid, 403 role field, 409 name taken |
| POST | `/login` | `{username, password}` | 200 `{token}` | 400, 401 bad creds, 429 locked |
| POST | `/records` | `{title, body}` + `Authorization: Bearer <token>` | 201 `{id}` | 400, 401, 403 role field |
| GET | `/records/<id>` | Bearer token | 200 if owner or admin | 401, 404 otherwise |
| POST | `/logout` (extra) | Bearer token | 204, token revoked | 401 |

## Layout

```
app/config.py      env-based config (no secrets in code)
app/security.py    scrypt hashing, token generation (pure crypto, no Flask/DB)
app/db.py          storage; every query parameterised
app/auth.py        session check, per-account lockout, object-level access rule
app/validation.py  type/length/format checks
app/routes.py      thin HTTP handlers
manage.py          admin creation CLI
tests/             access-control, privilege, lockout, session, validation, injection tests
```

## Security rules -> where enforced

| Rule | Implementation | Response |
|---|---|---|
| Password storage | scrypt (N=2^14, r=8, p=1), 16-byte random salt per user, HMAC-peppered | n/a |
| Broken access control | `auth.can_read_record` on every read: owner or admin | 404 |
| Privilege escalation | role hard-coded `user` on register; `role`-like keys -> 403; admin only via CLI | 403 |
| Input validation | `validation.py`: presence, type, length, format, unknown fields, 64 KB body cap | 400 |
| Injection | only `?` placeholders in `db.py` / `auth.py` | n/a |
| Brute force | 5 failures per **account** -> 15 min lock | 429 + `Retry-After` |
| Session integrity | opaque server-side token, checked on every request | 401 |

## Threat model

**Sessions - opaque random token (chosen over JWT).** `secrets.token_urlsafe(32)` (256-bit). Only its
SHA-256 is stored server-side. Every request looks the hash up and checks expiry (1 h default). Why not a JWT:
opaque tokens can be revoked instantly (logout, demotion, delete user) and carry no claims to forge or go stale;
a signed JWT would need a signing key and a revocation list to get the same properties. Trade-off: one DB lookup per request.

**Password storage.** scrypt is memory-hard, so GPU/ASIC cracking is expensive. The unique salt defeats
rainbow tables and makes identical passwords hash differently. Parameters are stored inside each hash, so they can
be raised later. Comparison is constant-time. Passwords are capped at 128 chars to stop hash-based CPU/memory DoS.
Unknown usernames are verified against a dummy hash so timing doesn't reveal which accounts exist.

**Per-record access check.** `GET /records/:id` loads the record and then requires
`record.owner_id == session_user.id OR session_user.role == 'admin'`. "Logged in" is never enough.
A record that is not yours returns the *same* 404 as one that doesn't exist, so ids can't be probed. Record ids are
random UUIDv4 (defence in depth - the ACL, not id secrecy, is the control). The owner of a new record comes from the
session, never from the request body (extra body fields are rejected).

**Preventing a user becoming admin.** (1) Registration hard-codes `role='user'`. (2) Any role-like field
(`role`, `is_admin`, ...) in a body -> 403. (3) There is no profile/update endpoint. (4) A DB `CHECK` limits role values.
(5) The role is read from the `users` table on every request, not stored in the token, so changes apply immediately.
(6) Admins are created only by `manage.py`, which needs shell access to the server.

**Login brute force.** Counted per username in a `login_attempts` table - *not* per IP, so rotating IPs doesn't help.
The attempt is counted atomically *before* the password is checked (inside a `BEGIN IMMEDIATE` transaction), so
parallel guesses can't slip past the limit. After 5 failures the 6th request gets 429 (even with the right password)
until the lock expires. Unknown usernames are throttled identically (no account enumeration). Success resets the counter.

**If the user table leaked - what an attacker could and could not recover.**
- *Could:* usernames, roles, creation times, and the scrypt hashes/salts. They learn who the admins are and could
  try offline guessing of very weak/common passwords - but only if they also get the pepper (below).
- *Could not:* plaintext passwords (no reversible storage). Not usable sessions: the sessions table holds only
  SHA-256 digests of 256-bit random tokens, which can't be turned back into the token. Not records' owners' credentials.
- *Pepper:* passwords are HMAC'd with `PASSWORD_PEPPER` (env var, not in the DB) before scrypt. A DB-only leak therefore
  can't even be cracked offline without the pepper. If the pepper leaks too, security falls back to scrypt + salt strength.
- *Note:* record titles/bodies are in the same DB and are **not** encrypted at rest here; a full DB leak exposes them
  (see limitations).

## Known limitations / what I'd do next
- Account lockout can be abused to lock a victim out for 15 min (DoS). Mitigation in prod: exponential backoff,
  CAPTCHA, alerting; per-IP limits layered on top as a second control.
- Record bodies are not encrypted at rest (would add envelope encryption with a KMS key).
- Run behind TLS and a real WSGI server (gunicorn); `run.py` is dev-only. Rate-limit `/register` at the proxy.
- Registration returns 409 for a taken username (enumeration trade-off, needed for usable sign-up).
- SQLite is fine for this scope; use Postgres (same parameterised queries) for multi-instance deployments.
