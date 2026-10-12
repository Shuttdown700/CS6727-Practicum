#!/usr/bin/env python3
"""
tools/adduser.py -- create an operator account, or change a password.

    python3 -m fabguard.tools.adduser

Interactive on purpose: a password passed as an argument lands in shell
history and in the process list.
"""

import getpass
import sys

from .. import config
from ..core import db, identity


def main() -> int:
    db.connect()
    users = {u["username"] for u in identity.list_users()}
    print(f"database: {config.DB_PATH}")
    print(f"existing: {', '.join(sorted(users)) or '(none)'}\n")

    username = input("username: ").strip().lower()
    if not username:
        print("aborted")
        return 1

    if username in users:
        print(f"'{username}' exists -- changing its password")
        pw = getpass.getpass("new password: ")
        if pw != getpass.getpass("confirm: "):
            print("passwords do not match")
            return 1
        try:
            identity.set_password(username, pw, actor="tools.adduser")
        except ValueError as exc:
            print(exc)
            return 1
        print(f"password changed for '{username}'")
        return 0

    display = input("display name: ").strip() or username
    pw = getpass.getpass("password: ")
    if pw != getpass.getpass("confirm: "):
        print("passwords do not match")
        return 1
    try:
        identity.create_user(username, pw, display, actor="tools.adduser")
    except ValueError as exc:
        print(exc)
        return 1
    print(f"created '{username}' ({display})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
