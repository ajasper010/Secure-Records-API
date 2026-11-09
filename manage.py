"""Admins are created ONLY here (server-side CLI) - there is no HTTP path that grants admin.

  python manage.py create-admin alice          (prompts for password)
  ADMIN_PASSWORD=... python manage.py create-admin alice   (non-interactive)
"""
import argparse
import getpass
import os
import sqlite3
import sys

from app import create_app, db, security, validation as v


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create-admin").add_argument("username")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        username = args.username.strip().lower()
        if not v.USERNAME_RE.match(username):
            sys.exit("invalid username")
        password = os.environ.get("ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
        if not (12 <= len(password) <= 128):
            sys.exit("admin password must be 12-128 characters")
        pw_hash = security.hash_password(password, app.config["PASSWORD_PEPPER"])
        try:
            db.create_user(username, pw_hash, "admin", security.now())
        except sqlite3.IntegrityError:
            sys.exit("username already exists")
        print(f"admin '{username}' created")


if __name__ == "__main__":
    main()
