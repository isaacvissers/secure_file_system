import sys
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from backend.auth import *


def ensure_admin_user(username: str, password: str, reset_password: bool = False):
    """Ensure an admin user exists. If `reset_password` is True and an admin
    record exists, remove it and recreate the admin user (simulate password reset).
    Returns a tuple of (user_dict_or_admin_data, status) where status is
    'created', 'updated', 'exists', or 'missing'.
    """
    admin_path = find_admin_record_path()
    if not admin_path:
        new_user = create_user(username, password, is_admin=True)
        return new_user, "created"

    if reset_password:
        try:
            admin_path.unlink()
        except Exception:
            pass
        new_user = create_user(username, password, is_admin=True)
        return new_user, "updated"

    admin = get_admin_record()
    if admin is None:
        return None, "missing"
    # return raw dict representation
    return admin.__dict__, "exists"


def main() -> None:
    admin_path = find_admin_record_path()
    if admin_path:
        print(f"Admin record found: {admin_path}")
        return

    print("No admin user found. Creating a new admin user.")
    username = ADMIN
    password = ADMIN

    new_user = create_user(username, password, is_admin=True)
    if new_user is None:
        print(f"Failed to create admin user: username '{username}' already exists.")
        return

    print(f"Created admin user: {username}")


if __name__ == "__main__":
    main()
