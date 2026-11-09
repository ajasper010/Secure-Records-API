import os
import sqlite3
import tempfile
import unittest

from app import create_app, db, security

PEPPER = "test-pepper-0123456789abcdef"
PW = "correct-horse-battery"


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.app = create_app({"DATABASE": self.path, "PASSWORD_PEPPER": PEPPER})
        self.c = self.app.test_client()

    def tearDown(self):
        os.remove(self.path)

    # helpers
    def reg(self, u, p=PW, **extra):
        return self.c.post("/register", json={"username": u, "password": p, **extra})

    def login(self, u, p=PW):
        return self.c.post("/login", json={"username": u, "password": p})

    def token(self, u, p=PW):
        self.reg(u, p)
        return self.login(u, p).get_json()["token"]

    def h(self, token):
        return {"Authorization": f"Bearer {token}"}

    def make_record(self, token, title="t", body="b"):
        r = self.c.post("/records", json={"title": title, "body": body}, headers=self.h(token))
        self.assertEqual(r.status_code, 201)
        return r.get_json()["id"]

    def make_admin(self, username="boss"):
        with self.app.app_context():
            ph = security.hash_password(PW, PEPPER)
            db.create_user(username, ph, "admin", security.now())
        return self.login(username).get_json()["token"]

    def raw(self, sql, args=()):
        conn = sqlite3.connect(self.path)
        rows = conn.execute(sql, args).fetchall()
        conn.commit()
        conn.close()
        return rows


class PasswordStorage(Base):
    def test_slow_salted_hash_no_plaintext(self):
        self.reg("alice")
        self.reg("bob")
        (h1,), (h2,) = self.raw("SELECT password_hash FROM users ORDER BY id")
        self.assertTrue(h1.startswith("scrypt$"))
        self.assertNotIn(PW, h1)
        self.assertNotEqual(h1, h2)  # same password, different salt -> different hash


class Registration(Base):
    def test_register_creates_user_role(self):
        r = self.reg("alice")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["role"], "user")

    def test_duplicate_username_409(self):
        self.reg("alice")
        self.assertEqual(self.reg("ALICE").status_code, 409)

    def test_cannot_register_as_admin(self):
        for extra in ({"role": "admin"}, {"Role": "admin"}, {"is_admin": True}, {"roles": ["admin"]}):
            self.assertEqual(self.reg("mallory", **extra).status_code, 403, extra)
        self.assertEqual(self.raw("SELECT COUNT(*) FROM users")[0][0], 0)

    def test_roles_in_db_are_user(self):
        self.reg("alice")
        self.assertEqual(self.raw("SELECT role FROM users")[0][0], "user")

    def test_role_field_on_record_create_is_403(self):
        t = self.token("alice")
        r = self.c.post("/records", json={"title": "x", "body": "y", "role": "admin"}, headers=self.h(t))
        self.assertEqual(r.status_code, 403)


class Validation(Base):
    def test_bad_register_inputs_400(self):
        bad = [
            {}, {"username": "alice"}, {"password": PW},
            {"username": 123, "password": PW}, {"username": "alice", "password": 12345678},
            {"username": "ab", "password": PW}, {"username": "a" * 33, "password": PW},
            {"username": "alice", "password": "short"}, {"username": "alice", "password": "x" * 129},
            {"username": "bad name!", "password": PW}, {"username": "alice", "password": PW, "x": 1},
            {"username": None, "password": PW}, {"username": ["a"], "password": PW},
        ]
        for body in bad:
            self.assertEqual(self.c.post("/register", json=body).status_code, 400, body)

    def test_non_json_and_malformed_400(self):
        self.assertEqual(self.c.post("/register", data="x=1").status_code, 400)
        self.assertEqual(self.c.post("/register", data="{bad", content_type="application/json").status_code, 400)
        self.assertEqual(self.c.post("/register", json=["a", "b"]).status_code, 400)
        self.assertEqual(self.c.post("/login", json="str").status_code, 400)

    def test_record_validation_400(self):
        t = self.token("alice")
        bad = [{}, {"title": "x"}, {"body": "x"}, {"title": 1, "body": "x"}, {"title": "x", "body": {"a": 1}},
               {"title": "", "body": "x"}, {"title": "   ", "body": "x"}, {"title": "x" * 201, "body": "x"},
               {"title": "x", "body": "y" * 10_001}, {"title": "x", "body": "y", "extra": 1}]
        for body in bad:
            self.assertEqual(self.c.post("/records", json=body, headers=self.h(t)).status_code, 400, body)

    def test_oversized_body_is_400_not_500(self):
        t = self.token("alice")
        r = self.c.post("/records", json={"title": "x", "body": "y" * 200_000}, headers=self.h(t))
        self.assertEqual(r.status_code, 400)

    def test_unknown_route_and_method_are_json(self):
        self.assertEqual(self.c.get("/nope").status_code, 404)
        self.assertEqual(self.c.get("/register").status_code, 405)


class Sessions(Base):
    def test_login_success_returns_token(self):
        self.reg("alice")
        r = self.login("alice")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(len(r.get_json()["token"]), 30)

    def test_bad_creds_401_same_for_unknown_user(self):
        self.reg("alice")
        self.assertEqual(self.login("alice", "wrong-password").status_code, 401)
        self.assertEqual(self.login("ghost", "wrong-password").status_code, 401)
        self.assertEqual(self.login("alice", "wrong-password").get_json(),
                         self.login("ghost", "wrong-password").get_json())

    def test_missing_tampered_and_forged_tokens_401(self):
        t = self.token("alice")
        rid = self.make_record(t)
        self.assertEqual(self.c.get(f"/records/{rid}").status_code, 401)
        self.assertEqual(self.c.get(f"/records/{rid}", headers=self.h(t + "x")).status_code, 401)
        self.assertEqual(self.c.get(f"/records/{rid}", headers=self.h("a" * 43)).status_code, 401)
        self.assertEqual(self.c.get(f"/records/{rid}", headers={"Authorization": t}).status_code, 401)
        self.assertEqual(self.c.get(f"/records/{rid}", headers={"Authorization": "Basic abc"}).status_code, 401)
        self.assertEqual(self.c.post("/records", json={"title": "a", "body": "b"}).status_code, 401)

    def test_expired_session_401(self):
        t = self.token("alice")
        rid = self.make_record(t)
        self.raw("UPDATE sessions SET expires_at = ?", (security.now() - 1,))
        self.assertEqual(self.c.get(f"/records/{rid}", headers=self.h(t)).status_code, 401)

    def test_logout_revokes_token(self):
        t = self.token("alice")
        self.assertEqual(self.c.post("/logout", headers=self.h(t)).status_code, 204)
        self.assertEqual(self.c.post("/records", json={"title": "a", "body": "b"}, headers=self.h(t)).status_code, 401)

    def test_raw_token_not_stored(self):
        t = self.token("alice")
        stored = self.raw("SELECT token_hash FROM sessions")[0][0]
        self.assertNotEqual(stored, t)
        self.assertEqual(stored, security.token_digest(t))

    def test_tokens_are_unique(self):
        self.reg("alice")
        self.assertNotEqual(self.login("alice").get_json()["token"], self.login("alice").get_json()["token"])


class AccessControl(Base):
    def test_owner_reads_own_record(self):
        t = self.token("alice")
        rid = self.make_record(t, "hello", "secret")
        r = self.c.get(f"/records/{rid}", headers=self.h(t))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["body"], "secret")

    def test_user_cannot_read_other_users_record(self):
        ta, tb = self.token("alice"), self.token("bob")
        rid = self.make_record(ta, "a", "alice-secret")
        r = self.c.get(f"/records/{rid}", headers=self.h(tb))
        self.assertIn(r.status_code, (403, 404))
        self.assertNotIn("alice-secret", r.get_data(as_text=True))

    def test_other_user_and_missing_look_identical(self):
        ta, tb = self.token("alice"), self.token("bob")
        rid = self.make_record(ta)
        other = self.c.get(f"/records/{rid}", headers=self.h(tb))
        missing = self.c.get("/records/00000000-0000-4000-8000-000000000000", headers=self.h(tb))
        self.assertEqual((other.status_code, other.get_json()), (missing.status_code, missing.get_json()))

    def test_admin_reads_any_record(self):
        ta = self.token("alice")
        rid = self.make_record(ta, "a", "alice-secret")
        r = self.c.get(f"/records/{rid}", headers=self.h(self.make_admin()))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["body"], "alice-secret")

    def test_record_owner_is_session_user_not_client_input(self):
        ta = self.token("alice")
        self.c.post("/records", json={"title": "a", "body": "b", "owner_id": 999}, headers=self.h(ta))
        self.assertEqual(self.raw("SELECT COUNT(*) FROM records")[0][0], 0)  # unknown field rejected
        self.make_record(ta)
        self.assertEqual(self.raw("SELECT owner_id FROM records")[0][0], 1)

    def test_demoted_admin_loses_access_immediately(self):
        ta = self.token("alice")
        rid = self.make_record(ta)
        admin = self.make_admin()
        self.assertEqual(self.c.get(f"/records/{rid}", headers=self.h(admin)).status_code, 200)
        self.raw("UPDATE users SET role = 'user' WHERE username = 'boss'")
        self.assertEqual(self.c.get(f"/records/{rid}", headers=self.h(admin)).status_code, 404)

    def test_malformed_record_ids_404(self):
        t = self.token("alice")
        for rid in ("1", "abc", "1 OR 1=1", "' OR '1'='1", "..%2f..%2fetc", "%00"):
            self.assertEqual(self.c.get(f"/records/{rid}", headers=self.h(t)).status_code, 404, rid)


class Injection(Base):
    def test_sql_injection_payloads_do_not_work(self):
        self.reg("alice")
        t = self.token("bob")
        self.make_record(t)
        for payload in ("' OR '1'='1", "alice'--", "admin' OR 1=1 --", "'; DROP TABLE users;--"):
            self.assertEqual(self.c.post("/login", json={"username": payload, "password": PW}).status_code, 400)
            self.assertEqual(self.c.post("/login", json={"username": "alice", "password": payload}).status_code, 401)
        self.assertEqual(self.raw("SELECT COUNT(*) FROM users")[0][0], 2)  # tables intact


class LoginLockout(Base):
    def test_lockout_after_5_failures_returns_429(self):
        self.reg("alice")
        codes = [self.login("alice", "wrong-password").status_code for _ in range(5)]
        self.assertEqual(codes, [401] * 5)
        r = self.login("alice", "wrong-password")
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r.headers)

    def test_correct_password_still_blocked_while_locked(self):
        self.reg("alice")
        for _ in range(6):
            self.login("alice", "wrong-password")
        self.assertEqual(self.login("alice", PW).status_code, 429)

    def test_lockout_is_per_account_not_per_ip(self):
        self.reg("alice")
        self.reg("bob")
        for _ in range(7):
            self.login("alice", "wrong-password")
        self.assertEqual(self.login("alice", PW).status_code, 429)
        self.assertEqual(self.login("bob", PW).status_code, 200)  # same client IP, other account fine

    def test_lockout_applies_to_unknown_usernames_too(self):
        for _ in range(5):
            self.login("ghost", "x")
        self.assertEqual(self.login("ghost", "x").status_code, 429)

    def test_success_resets_counter(self):
        self.reg("alice")
        for _ in range(4):
            self.login("alice", "wrong-password")
        self.assertEqual(self.login("alice", PW).status_code, 200)
        for _ in range(4):
            self.assertEqual(self.login("alice", "wrong-password").status_code, 401)

    def test_lock_expires(self):
        self.reg("alice")
        for _ in range(6):
            self.login("alice", "wrong-password")
        self.raw("UPDATE login_attempts SET locked_until = ?, last_attempt = ?",
                 (security.now() - 1, security.now() - 10_000))
        self.assertEqual(self.login("alice", PW).status_code, 200)


if __name__ == "__main__":
    unittest.main()
