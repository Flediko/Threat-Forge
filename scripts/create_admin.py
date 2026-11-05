"""
CLI Script to Create an Administrator Account (Django Folder)
=============================================================
Prompts interactively for username, email, and password (using ``getpass``)
and creates an ``admin`` user in ``data/threatforge.db``.

Usage:
    cd threatforge_django
    python scripts/create_admin.py
"""

import getpass
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.activity import log_event
from services.auth import hash_password, validate_registration_input
from services.db import (
    create_user,
    get_user_by_email,
    get_user_by_username,
    init_db,
)


def main() -> int:
    init_db()
    print("=" * 55)
    print("  ThreatForge — Create Administrator Account (Django)")
    print("=" * 55)

    username = input("Admin username (3-30 chars, letters/digits/_): ").strip()
    email = input("Admin email address: ").strip().lower()
    password = getpass.getpass("Admin password (min 10 chars, letter + digit): ")
    confirm = getpass.getpass("Confirm admin password: ")

    if password != confirm:
        print("[!] Error: Passwords do not match.")
        return 1

    err = validate_registration_input(username, email, password)
    if err:
        print(f"[!] Validation error: {err}")
        return 1

    if get_user_by_username(username):
        print(f"[!] Error: Username '{username}' already exists.")
        return 1

    if get_user_by_email(email):
        print(f"[!] Error: Email '{email}' is already registered.")
        return 1

    pwd_hash, salt_hex = hash_password(password)
    user_id = create_user(
        username=username,
        email=email,
        password_hash=pwd_hash,
        salt=salt_hex,
        role="admin",
    )
    log_event(
        action="admin_created",
        user_id=user_id,
        username=username,
        detail=f"Administrator account '{username}' created via CLI script",
    )
    print(f"\n[+] Administrator account '{username}' (id={user_id}) created successfully!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

