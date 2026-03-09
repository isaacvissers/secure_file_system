import json
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from backend.cryptography_utils import *
from backend.group_utils import add_user_to_group, load_group, save_group
from models.directory import Directory
from models.user import AdminUser, User

SRC_DIR = Path(__file__).resolve().parents[1]
USERS_DIR = SRC_DIR / "storage/.users"
USERS_DIR.mkdir(parents=True, exist_ok=True)

FILES_DIR = SRC_DIR / "storage/files"
FILES_DIR.mkdir(parents=True, exist_ok=True)

SALT_BYTES = 16
ADMIN = "admin"
SALT = "psalt"

UserDict = Dict[str, Any]

# --------------------
# Auth Wrappers
# --------------------


def requires_login(func):
    @wraps(func)
    def wrapper(self, arg):
        if not getattr(self, "current_user", None):
            print("Must be logged in.")
            return
        return func(self, arg)

    return wrapper


def requires_admin(func):
    @wraps(func)
    @requires_login
    def wrapper(self, arg):
        if not isinstance(self.current_user, AdminUser):
            print("Must be logged in as Admin")
            return
        return func(self, arg)

    return wrapper


def requires_logged_out(func):
    @wraps(func)
    def wrapper(self, arg):
        if getattr(self, "current_user", None):
            print("Already logged in.")
            return
        return func(self, arg)

    return wrapper


# --------------------
# Key Utilities
# --------------------


def create_user_key(username: str, password: str) -> str:
    """Generate a user key. Replace with proper encryption later."""
    return f"{username}_{password}_{SALT}"


def get_admin_key() -> str:
    return create_user_key(ADMIN, ADMIN)


def _user_file_path(user_key: str) -> Path:
    return USERS_DIR / f"{user_key}.json"


# --------------------
# Admin Utilities
# --------------------


def get_admin_record() -> Optional[AdminUser]:
    """Return the AdminUser object if exists."""
    path = _user_file_path(get_admin_key())
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        return AdminUser(**data)


def _get_admin_or_fail() -> Optional[AdminUser]:
    admin = get_admin_record()
    if not admin:
        print("Admin record not found.")
    return admin


def add_user_key_to_admin(username: str, user_key: str) -> None:
    admin = _get_admin_or_fail()
    if not admin:
        return

    if getattr(admin, "user_keys", None) is None:
        admin.user_keys = {}

    admin.user_keys[username] = user_key
    save_user(get_admin_key(), admin.__dict__)


# --------------------
# User Storage
# --------------------


def save_user(user_key: str, user_dict: UserDict) -> None:
    """Save user JSON to disk (future: encrypt here)."""
    path = _user_file_path(user_key)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(user_dict, f)


def load_user(username: str) -> Optional[UserDict]:
    """Load user by username, using admin index first, then fallback scan."""
    admin = get_admin_record()
    if admin and getattr(admin, "user_keys", None):
        user_key = admin.user_keys.get(username)
        if user_key:
            path = _user_file_path(user_key)
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    return None

    # fallback: scan all users
    for f in USERS_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            continue
        if data.get("username") == username:
            return data
    return None


def user_exists(username: str) -> bool:
    return load_user(username) is not None


# --------------------
# User Creation
# --------------------


def create_user(
    username: str, password: str, is_admin: bool = False
) -> Optional[UserDict]:
    """Create a new user or admin. Returns user dict."""
    if user_exists(username):
        print(f"User '{username}' already exists.")
        return None

    user_key = create_user_key(username, password)
    user_dict: UserDict = {
        "username": username,
        "file_keys": [],
        "group_keys": [],
    }

    if is_admin:
        user_dict["user_keys"] = {}
        user_dict["group_keys"] = {}

    save_user(user_key, user_dict)
    add_user_key_to_admin(username, user_key)

    if not is_admin:
        create_user_directory(user_dict["username"])

        added_to_group = add_user_to_group("all", username)
        if not added_to_group:
            print(f"Failed to add user '{username}' to group 'all'.")
            return
    return user_dict


def create_user_directory(username: str) -> Path:
    """Create the home directory for a new user under FILES_DIR."""
    return Directory.create(FILES_DIR, username)


# --------------------
# User Helpers
# --------------------


def _resolve_user(
    admin: AdminUser, username: str
) -> Tuple[Optional[str], Optional[UserDict]]:
    """Return (user_key, user_dict). Print errors if missing."""
    user_key = admin.user_keys.get(username)
    if not user_key:
        print(f"User '{username}' not found.")
        return None, None

    user = load_user(username)
    if not user:
        print("User file not found.")
        return None, None

    return user_key, user
