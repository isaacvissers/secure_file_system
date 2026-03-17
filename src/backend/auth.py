import json
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# from backend.cryptography_utils import *
from backend.group_utils import add_user_to_group
from backend.storage_paths import get_storage_dir
from models.directory import Directory
from models.user import AdminUser, User

STORAGE_DIR = get_storage_dir()
USERS_DIR = STORAGE_DIR / ".users"
USERS_DIR.mkdir(parents=True, exist_ok=True)

FILES_DIR = STORAGE_DIR / "files"
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
# User Storage
# --------------------


def create_user_directory(user: User) -> Path:
    """Create the home directory for a new user under FILES_DIR."""
    return Directory.create(FILES_DIR, user.username, user)


# --------------------
# User Helpers
# --------------------


def add_user_to_admin(admin: AdminUser, target_user: User, user_master_key: str):
    """
    Adds a new user to the admin's user_keys
    """
    file_id = Path(target_user.path).name
    admin.user_keys[target_user.username] = {"id": file_id, "key": user_master_key}

    admin.save()
