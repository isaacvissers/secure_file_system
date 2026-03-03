import argparse
import json
import os
import sys
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from backend.auth import USERS_DIR, create_user
from backend.cryptography_utils import hash_password

UserDict = Dict[str, Any]


def _iter_user_records() -> Iterator[Tuple[Path, UserDict]]:
    for file_path in USERS_DIR.glob("*.json"):
        with open(file_path, "r") as file:
            yield file_path, json.load(file)


def _write_user_file(file_path: Path, user_dict: UserDict) -> None:
    with open(file_path, "w") as file:
        json.dump(user_dict, file)


def _find_user_record(username: str) -> Tuple[Optional[Path], Optional[UserDict]]:
    for file_path, user_data in _iter_user_records():
        if user_data.get("username") == username:
            return file_path, user_data
    return None, None


def ensure_admin_user(
    username: str, password: str, reset_password: bool = False
) -> Tuple[UserDict, str]:
    file_path, existing_user = _find_user_record(username)

    if existing_user is None:
        created_user = create_user(username, password, is_admin=True)
        if created_user is None:
            raise RuntimeError("Failed to create admin user.")
        return created_user, "created"

    updated = False
    if not existing_user.get("is_admin", False):
        existing_user["is_admin"] = True
        updated = True

    if reset_password:
        salt = os.urandom(16)
        password_hash = hash_password(password.encode(), salt)
        existing_user["salt"] = salt.hex()
        existing_user["password_hash"] = password_hash.hex()
        updated = True

    if updated and file_path is not None:
        _write_user_file(file_path, existing_user)
        return existing_user, "updated"

    return existing_user, "unchanged"


def _prompt_password_if_missing(password: str | None) -> str:
    if password:
        return password

    first = getpass("Admin password: ")
    return first


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create or recover an admin user account."
    )
    parser.add_argument(
        "--username", default="admin", help="Admin username (default: admin)"
    )
    parser.add_argument("--password", help="Admin password (omit to be prompted)")
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="Reset password if the admin user already exists",
    )
    args = parser.parse_args()

    password = _prompt_password_if_missing(args.password)
    user_data, status = ensure_admin_user(
        username=args.username,
        password=password,
        reset_password=args.reset_password,
    )

    print(f"Admin status: {status}")
    print(f"Username: {user_data['username']}")
    print(f"User ID: {user_data['user_id']}")


if __name__ == "__main__":
    main()
