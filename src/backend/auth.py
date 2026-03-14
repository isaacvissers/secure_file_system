import json
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from backend.group_utils import add_user_to_group, create_group, load_group
from models.directory import Directory
from models.user import AdminUser

SRC_DIR = Path(__file__).resolve().parents[1]
USERS_DIR = SRC_DIR / "storage/.users"
USERS_DIR.mkdir(parents=True, exist_ok=True)

FILES_DIR = SRC_DIR / "storage/files"
FILES_DIR.mkdir(parents=True, exist_ok=True)

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


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)


def _serialize_user_record(user_key: str, user_dict: UserDict) -> Dict[str, Any]:
    """Serialization hook for user records (future: encrypt here)."""
    _ = user_key
    return user_dict


def _deserialize_user_record(
    user_key: str, record: Optional[Dict[str, Any]]
) -> Optional[UserDict]:
    """Deserialization hook for user records (future: decrypt here)."""
    _ = user_key
    if not isinstance(record, dict):
        return None
    return record


# --------------------
# Admin Utilities
# --------------------


def get_admin_record() -> Optional[AdminUser]:
    """Return the AdminUser object if exists."""
    admin_key = get_admin_key()
    raw = _read_json(_user_file_path(admin_key))
    data = _deserialize_user_record(admin_key, raw)
    if data is None:
        return None

    admin_payload = {
        "username": data.get("username", ADMIN),
        "file_keys": data.get("file_keys", {}),
        "group_keys": data.get("group_keys", {}),
        "user_keys": data.get("user_keys", {}),
    }
    return AdminUser(**admin_payload)


def _save_admin_record(admin: AdminUser) -> None:
    save_user(get_admin_key(), admin.__dict__)


def _get_admin_or_fail(admin: Optional[AdminUser] = None) -> Optional[AdminUser]:
    admin = admin or get_admin_record()
    if not admin:
        print("Admin record not found.")
    return admin


def add_user_key_to_admin(
    username: str, user_key: str, admin: Optional[AdminUser] = None
) -> Optional[AdminUser]:
    admin = _get_admin_or_fail(admin)
    if not admin:
        return None

    if getattr(admin, "user_keys", None) is None:
        admin.user_keys = {}

    admin.user_keys[username] = user_key
    _save_admin_record(admin)
    return admin


# --------------------
# User Storage
# --------------------


def save_user(user_key: str, user_dict: UserDict) -> None:
    """Save user record to disk (serialization hook supports future encryption)."""
    path = _user_file_path(user_key)
    payload = _serialize_user_record(user_key, user_dict)
    _write_json(path, payload)


def _load_user_by_key(user_key: str) -> Optional[UserDict]:
    raw = _read_json(_user_file_path(user_key))
    return _deserialize_user_record(user_key, raw)


def _scan_user_by_username(username: str) -> Optional[UserDict]:
    for path in USERS_DIR.glob("*.json"):
        raw = _read_json(path)
        data = _deserialize_user_record(path.stem, raw)
        if data and data.get("username") == username:
            return data
    return None


def load_user(username: str, admin: Optional[AdminUser] = None) -> Optional[UserDict]:
    """Load user by username, using admin index first, then fallback scan."""
    admin_supplied = admin is not None
    admin = admin or get_admin_record()

    if admin and getattr(admin, "user_keys", None):
        user_key = admin.user_keys.get(username)
        if user_key:
            return _load_user_by_key(user_key)
        if admin_supplied:
            return None

    if admin_supplied:
        return None

    return _scan_user_by_username(username)


def user_exists(username: str, admin: Optional[AdminUser] = None) -> bool:
    if admin and username in getattr(admin, "user_keys", {}):
        return True
    return load_user(username, admin=admin) is not None


def user_exists_with_admin(username: str, admin: Optional[AdminUser] = None) -> bool:
    return user_exists(username, admin=admin)


# --------------------
# User Creation
# --------------------


def create_user(
    username: str,
    password: str,
    is_admin: bool = False,
    admin: Optional[AdminUser] = None,
) -> Optional[UserDict]:
    """Create a new user or admin. Returns user dict."""
    if user_exists(username, admin=admin):
        print(f"User '{username}' already exists.")
        return None

    user_key = create_user_key(username, password)
    user_dict: UserDict = {
        "username": username,
        "file_keys": {},
        "group_keys": [],
    }

    if is_admin:
        user_dict["user_keys"] = {}
        user_dict["group_keys"] = {}

    save_user(user_key, user_dict)
    admin = add_user_key_to_admin(username, user_key, admin=admin)

    if not is_admin:
        create_user_directory(user_dict["username"])

        if load_group("all", admin=admin) is None:
            create_group("all", admin=admin)

        added_to_group = add_user_to_group("all", username, admin=admin)
        if not added_to_group:
            print(f"Failed to add user '{username}' to group 'all'.")
            return
    return user_dict


def create_user_directory(username: str) -> Path:
    """Create the home directory for a new user under FILES_DIR."""
    return Directory.create(FILES_DIR, username, username)


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

    user = load_user(username, admin=admin)
    if not user:
        print("User file not found.")
        return None, None

    return user_key, user
