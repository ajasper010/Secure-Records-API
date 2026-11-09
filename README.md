# Secure Records API

A small, secure backend where users sign in, create records, and can read **only their own** records.
An **admin** can read any record.

Built for the Nestack Cybersecurity take-home. Python + Flask + SQLite.
**No auth library is used** - sessions, access control and login limits are written by hand.

---

## 1. Quick start

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env        # then open .env and set PASSWORD_PEPPER to a long random value
                            # generate one: python -c "import secrets; print(secrets.token_hex(32))"

python run.py               # API now runs at http://127.0.0.1:5000
```

Run the tests (32 tests, all passing):
```bash
python -m unittest discover -s tests -t . -v
```

Create an admin (admins can **only** be created this way, never through the API):
```bash
python manage.py create-admin alice
```

---

## 2. What the API does

| Method | Endpoint | Send | Success | Errors |
|---|---|---|---|---|
| POST | `/register` | `{username, password}` | **201** (always a normal `user`) | 400 bad input, 403 role field sent, 409 name taken |
| POST | `/login` | `{username, password}` | **200** + session token | 400, 401 wrong login, **429** locked out |
| POST | `/records` | `{title, body}` + token | **201** + new record id | 400, 401, 403 |
| GET | `/records/<id>` | token | **200** if yours (or admin) | 401, **404** otherwise |
| POST | `/logout` *(extra)* | token | 204, token is revoked | 401 |

Send the token as a header: `Authorization: Bearer <token>`

---

## 3. See it working

Real output from a running server:

```bash
# Register a normal user
$ curl -XPOST /register -d '{"username":"alice","password":"alice-password-1"}'
{"id":2,"role":"user","username":"alice"}                        -> 201

# Try to sneak in as admin
$ curl -XPOST /register -d '{"username":"evil","password":"evil-password-1","role":"admin"}'
{"error":"role/privilege fields cannot be set by clients"}       -> 403

# Alice reads her own record
$ curl /records/<id> -H "Authorization: Bearer <alice token>"
{"body":"alice secret","title":"t", ...}                         -> 200

# Bob tries to read Alice's record
$ curl /records/<id> -H "Authorization: Bearer <bob token>"
{"error":"record not found"}                                     -> 404

# Admin reads Alice's record
$ curl /records/<id> -H "Authorization: Bearer <admin token>"
{"body":"alice secret","title":"t", ...}                         -> 200

# No token at all
$ curl /records/<id>
{"error":"authentication required"}                              -> 401

# 6 wrong passwords in a row for one account
401 401 401 401 401 429                                          -> locked out
```

What is stored in the database (passwords are never readable):
```
('boss',  'admin', 'scrypt$16384$8$1$BymWn5qTWtWOp4GJ...')
('alice', 'user',  'scrypt$16384$8$1$R7JheeA8CRdILGcw...')
```

---

## 4. How each requirement is met

| Requirement | How |
|---|---|
| **Passwords** | Hashed with **scrypt** (slow and memory-hungry) with a **unique random salt** per user. Never plaintext, never a fast hash. |
| **Sessions** | On login the server makes a **random 256-bit token**. Only a SHA-256 *fingerprint* of it is saved. Every request is checked against the database. Tokens expire after 1 hour. |
| **Users see only their own records** | On every read the server checks: *is this record's owner the logged-in user, or is the user an admin?* If not -> 404. |
| **Admin role** | Set **only on the server** (`manage.py`). Registration always creates a normal user. Any `role` field in a request is rejected with 403. |
| **Input validation** | Every field is checked for presence, type and length. Wrong or oversized input gets a clean **400**, never a crash/stack trace. |
| **SQL injection** | Every query uses `?` placeholders. No string-built SQL anywhere. |
| **Brute force** | **5 failed logins on an account** -> that account is locked for 15 minutes (**429**). Counted **per account, not per IP**. |

---

## 5. Project layout

```
app/
  config.py       settings from environment variables (no secrets in code)
  security.py     password hashing + token generation
  db.py           database queries (all parameterised)
  auth.py         login check, lockout logic, "can this user read this record?"
  validation.py   input checks
  routes.py       the 4 endpoints (+ logout)
manage.py         create an admin from the command line
run.py            start the server
tests/            32 automated tests
.env.example      example settings (the real .env is git-ignored)
```
Each file has one job: routes handle HTTP, auth handles identity and access, db handles storage, security handles crypto.

---

## 6. Threat model

**How a password is stored and why.** scrypt + a random salt per user. scrypt is deliberately slow and uses a lot of memory, which makes guessing passwords at scale very expensive. The salt means two users with the same password get different hashes, and pre-computed tables are useless. I also mix in a secret **pepper** (from the environment, *not* the database) before hashing.

**How a session is proven on each request.** The client sends its token. The server hashes it and looks it up in the `sessions` table, checking it exists and has not expired. I chose **opaque server-side tokens instead of JWT** because they can be revoked instantly (logout, demotion) and contain nothing an attacker could forge.

**How the per-record access check works.** After loading a record the server requires `owner == logged-in user` **or** `role == admin`. Being logged in is never enough. A record that isn't yours returns the *same* 404 as one that doesn't exist, so attackers can't discover which ids exist. Ids are random UUIDs, and the owner is always taken from the session, never from the request body.

**How a user is prevented from becoming admin.** Registration hard-codes `role = user`; any role-like field gives 403; there is no profile-edit endpoint; the database only allows `user` or `admin`; the role is read from the database on every request (not from the token), and the only way to create an admin is the server-side `manage.py` command.

**How brute force is stopped.** Attempts are counted per username *before* the password is checked, inside a database transaction, so many parallel guesses can't sneak past the limit. Unknown usernames are limited the same way, so the lockout doesn't reveal which accounts exist. A successful login resets the counter.

### If the user table leaked, what could an attacker get?

| Could get | Could NOT get |
|---|---|
| Usernames and who the admins are | Plaintext passwords (nothing reversible is stored) |
| Salted scrypt hashes (offline guessing is slow, and needs the pepper, which is not in the DB) | Working session tokens (only SHA-256 fingerprints of 256-bit random tokens are stored) |
| | Any way to log in directly using the stolen data |

Honest caveat: record titles and bodies live in the same database and are **not encrypted at rest**, so a full database leak would expose them.

---

## 7. Known limitations (what I'd do next)

- An attacker can deliberately lock someone's account for 15 minutes. In production: backoff, CAPTCHA, alerts, plus per-IP limits as a second layer.
- Encrypt record bodies at rest.
- Run behind HTTPS with a real server (e.g. gunicorn); `run.py` is for development.
- `/register` should also be rate-limited at the proxy.
