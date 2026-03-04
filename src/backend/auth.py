import json
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional

from backend.files_utils import create_user_directory
from backend.group_utils import load_group, save_group
from models.user import AdminUser, User

SRC_DIR = Path(__file__).resolve().parents[1]
USERS_DIR = SRC_DIR / "storage/.users"
USERS_DIR.mkdir(parents=True, exist_ok=True)
ADMIN = "admin"
SALT = "psalt"

UserDict = Dict[str, Any]


## --------------------
# Auth Wrappers
## --------------------
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
        is_admin = isinstance(current, AdminUser)

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


## --------------------
# User Management
## --------------------


# TODO: ADD ENCRYPTION
def create_user_key(username: str, password: str):
    user_key = f"{username}_{password}_{SALT}"
    return user_key


def get_admin_key():
    return create_user_key(ADMIN, ADMIN)


def find_user_record_path(user_key: bytes) -> Optional[Path]:
    pattern = "**/*"
    if isinstance(user_key, bytes):
        user_key = user_key.hex()
    for p in USERS_DIR.glob(pattern):
        if not p.is_file():
            continue
        if True and p.stem == user_key:
            return p
        if False and key in p.name:
            return p
    return None


def find_admin_record_path(*, exact=True, recursive=True):
    admin_key = get_admin_key()
    return find_user_record_path(admin_key)


# TODO: Add decryption
def get_admin_record() -> Optional[AdminUser]:
    admin_path = find_admin_record_path()
    if not admin_path:
        return None
    with open(admin_path, "r", encoding="utf-8") as file:
        admin_data = json.load(file)
        return AdminUser(**admin_data)


# TODO: Add decryption
def get_user_record_by_username(username: str) -> Optional[User]:
    admin = get_admin_record()
    if not admin:
        return None
    user_key = admin.user_keys.get(username)
    if not user_key:
        print(f"User '{username}' not found in admin record.")
        return None
    user_path = find_user_record_path(user_key)
    if not user_path:
        print(f"User file for '{username}' not found at expected path: {user_path}")
        return None
    with open(user_path, "r", encoding="utf-8") as file:
        user_data = json.load(file)
        if "user_keys" in user_data:
            return AdminUser(**user_data)
        return User(**user_data)


def create_user(
    username: str, password: str, is_admin: bool = False
) -> Optional[UserDict]:
    if user_exists(username):
        return None

    user_key = create_user_key(username, password)
    user_dict = {
        "username": username,
        "file_keys": [],
        "group_keys": [],
    }

    if not is_admin:
        save_user(user_key, user_dict)
        add_user_key_to_admin(username, user_key)
        create_user_directory(user_key)
    else:
        user_dict["user_keys"] = {}
        user_dict["group_keys"] = {}
        save_user(user_key, user_dict)
        add_user_key_to_admin(username, user_key)
    return user_dict


def write_user_file(file_path: Path, user_dict: UserDict) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(user_dict, file)


def user_exists(username: str) -> bool:
    return load_user(username) is not None


def save_user(user_key: bytes, user_dict: UserDict) -> None:
    user_file = USERS_DIR / f"{user_key}.json"
    write_user_file(user_file, user_dict)


def add_user_key_to_admin(username: str, user_key: bytes) -> None:
    admin = get_admin_record()
    if not admin:
        print("Admin record not found. Cannot add user key.")
        return

    if getattr(admin, "user_keys", None) is None:
        admin.user_keys = {}

    admin.user_keys[username] = user_key
    save_user(get_admin_key(), admin.__dict__)


def load_user(username: str) -> Optional[UserDict]:
    # Prefer admin index lookup (maps username -> user_key)
    admin = get_admin_record()
    if admin and getattr(admin, "user_keys", None):
        user_key = admin.user_keys.get(username)
        if user_key:
            p = find_user_record_path(user_key)
            if p:
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        return json.load(fh)
                except Exception:
                    return None
    # Fallback: scan all user files for a matching username field
    for f in USERS_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            continue
        if data.get("username") == username:
            return data
    return None
