import json
import os
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

from backend.cryptography_utils import *
from backend.group_utils import load_group, save_group

SRC_DIR = Path(__file__).resolve().parents[1]
USERS_DIR = SRC_DIR / "storage/.users"
USERS_DIR.mkdir(parents=True, exist_ok=True)
SALT_BYTES = 16

UserDict = Dict[str, Any]


def _iter_user_records() -> Iterator[Tuple[Path, UserDict]]:
    for file_path in USERS_DIR.glob("*.json"):
        with open(file_path, "r", encoding="utf-8") as file:
            yield file_path, json.load(file)


def _write_user_file(file_path: Path, user_dict: UserDict) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(user_dict, file)


def _find_user_by_username(username: str) -> Optional[UserDict]:
    for _, user_data in _iter_user_records():
        if user_data.get("username") == username:
            return user_data
    return None


def _next_user_id() -> int:
    highest_user_id = 0
    for _, user_data in _iter_user_records():
        user_id = user_data.get("user_id", 0)
        if isinstance(user_id, int) and user_id > highest_user_id:
            highest_user_id = user_id
    return highest_user_id + 1


def requires_login(func):
    @wraps(func)
    def wrapper(self, arg):
        if not self.current_user:
            print("Must be logged in.")
            return
        return func(self, arg)

    return wrapper


def requires_admin(func):
    @wraps(func)
    @requires_login
    def wrapper(self, arg):
        current = self.current_user or {}
        is_admin = current.get("is_admin", False)
        if not is_admin and isinstance(current.get("user_data"), dict):
            is_admin = current["user_data"].get("is_admin", False)

        if not is_admin:
            print("Must be logged in as the Admin")
            return
        return func(self, arg)

    return wrapper


def requires_logged_out(func):
    @wraps(func)
    def wrapper(self, arg):
        if self.current_user:
            print("Already logged in.")
            return
        return func(self, arg)

    return wrapper


def user_exists(username: str) -> bool:
    return _find_user_by_username(username) is not None


def save_user(user_dict: UserDict) -> None:
    user_file = USERS_DIR / f"user_{user_dict['user_id']}.json"
    _write_user_file(user_file, user_dict)


def load_user(username: str) -> Optional[UserDict]:
    return _find_user_by_username(username)


def create_user(
    username: str, password: str, is_admin: bool = False
) -> Optional[UserDict]:
    if user_exists(username):
        return None

    salt = os.urandom(SALT_BYTES)
    password_hash = hash_password(password.encode(), salt)
    private_bytes, public_bytes = generate_rsa_keys()
    encrypted_private_key, nonce = encrypt_private_key(
        private_bytes, salt, password.encode()
    )

    user_dict = {
        "user_id": _next_user_id(),
        "username": username,
        "salt": salt.hex(),
        "password_hash": password_hash.hex(),
        "is_admin": is_admin,
        "public_key": public_bytes.hex(),
        "encrypted_private_key": encrypted_private_key.hex(),
        "private_key_nonce": nonce.hex(),
    }
    save_user(user_dict)
    return user_dict
