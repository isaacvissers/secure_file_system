"""
create_admin.py - Reset storage and bootstrap a fresh admin.

Usage:
    python scripts/create_admin.py
    python scripts/create_admin.py <username>
"""

import argparse
import hashlib
import os
import shutil
import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from backend.auth import STORAGE_DIR
from backend.group_utils import add_group_to_user
from models.group import GROUPS_DIR, Group
from models.user import AdminUser

STORAGE_SUBDIRS = ["files", ".groups", ".users"]


def clear_storage(yes: bool = False) -> bool:
    """Clear storage subdirectories while preserving the root storage folder."""
    if not STORAGE_DIR.exists():
        print(f"Storage directory not found: {STORAGE_DIR}")
        return False

    total = sum(
        1
        for subdir in STORAGE_SUBDIRS
        for _ in (STORAGE_DIR / subdir).rglob("*")
        if (STORAGE_DIR / subdir).exists()
    )

    if total == 0:
        print("Storage is already empty.")
        return True

    print(f"This will permanently delete {total} item(s) under {STORAGE_DIR}")

    if not yes:
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Aborted.")
            return False

    for name in STORAGE_SUBDIRS:
        subdir = STORAGE_DIR / name
        if not subdir.exists():
            continue
        for child in subdir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    print("Storage cleared.")
    return True


def _admin_user_path(username: str) -> Path:
    users_dir = STORAGE_DIR / ".users"
    users_dir.mkdir(parents=True, exist_ok=True)
    encrypted_name = hashlib.sha256(username.encode("utf-8")).hexdigest()
    return users_dir / encrypted_name


def ensure_admin_user(username: str) -> bool:
    """Verify whether the admin record exists on disk."""
    admin_path = _admin_user_path(username)
    return admin_path.exists()


def ensure_group(name: str) -> bool:
    """Verify whether a group's record exists on disk."""
    encrypted_name = hashlib.sha256(name.encode("utf-8")).hexdigest()
    group_path = GROUPS_DIR / encrypted_name
    return group_path.exists()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clear storage and create a fresh admin setup."
    )
    parser.add_argument("username", nargs="?", help="Admin username")
    return parser.parse_args()


def _parse_username(cli_username: str | None) -> str:
    if cli_username and cli_username.strip():
        return cli_username.strip()

    entered = input("Enter admin username: ").strip()
    if not entered:
        raise ValueError("Admin username cannot be empty")
    return entered


def main() -> None:
    args = _parse_args()

    print(f"Storage directory: {STORAGE_DIR}")

    if not clear_storage(yes=True):
        return

    username = "admin"

    admin_user, admin_key = AdminUser.create(username, username)
    if ensure_admin_user(username):
        print(f"Admin user created")
    else:
        print("Admin user record missing after create. Re-run setup script.")

    all_group, group_master_key = Group.create("all")
    if ensure_group("all"):
        print("All group created")
        key_material = admin_key if isinstance(admin_key, bytes) else admin_key.encode()
        add_group_to_user(admin_user, all_group, group_master_key, key_material)
        admin_user.save(key_material)
    else:
        print("All group record missing after create. Re-run setup script.")


if __name__ == "__main__":
    main()
