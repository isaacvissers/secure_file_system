import hashlib
import json
import os
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from backend.cryptography_utils import (
    create_password_to_verify,
    decrypt_with_key,
    encrypt_with_key,
    verify_password,
)
from backend.group_utils import add_user_to_group, create_group, load_group
from models.directory import Directory
from models.user import AdminUser

SRC_DIR = Path(__file__).resolve().parents[1]
USERS_DIR = SRC_DIR / "storage/.users"
USERS_DIR.mkdir(parents=True, exist_ok=True)

FILES_DIR = SRC_DIR / "storage/files"
FILES_DIR.mkdir(parents=True, exist_ok=True)

ADMIN = "admin"
ADMIN_RECORD_KEY_SALT = "admin_record_salt_v1"
ADMIN_FILENAME_SALT = "admin_filename_salt_v1"

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


def create_admin_login_token(username: str, password: str) -> str:
    """Derive a deterministic token string used for admin bootstrap/auth checks."""
    return f"{username}_{password}"


def get_admin_key() -> str:
    return create_admin_login_token(ADMIN, ADMIN)


def _get_admin_storage_name() -> str:
    material = f"{ADMIN_FILENAME_SALT}:{ADMIN}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _user_file_path(user_key: str) -> Path:
    storage_name = (
        _get_admin_storage_name() if user_key == get_admin_key() else user_key
    )
    return USERS_DIR / f"{storage_name}.json"


def _read_record_bytes(path: Path) -> Optional[bytes]:
    if not path.exists():
        return None
    try:
        return path.read_bytes()
    except Exception:
        return None


def _deserialize_user_record(
    record: Optional[bytes], record_key: bytes
) -> Optional[UserDict]:
    """Deserialize encrypted user bytes."""
    if record is None:
        return None

    try:
        decrypted = decrypt_with_key(record, record_key)
        user_data = json.loads(decrypted.decode("utf-8"))
    except Exception:
        return None

    if not isinstance(user_data, dict):
        return None
    return user_data


def _derive_admin_record_key(admin_key: str) -> bytes:
    material = f"{ADMIN_RECORD_KEY_SALT}:{admin_key}".encode("utf-8")
    return hashlib.sha256(material).digest()


def _parse_user_index_entry(entry: Any) -> Tuple[Optional[str], Optional[bytes]]:
    if not isinstance(entry, dict):
        return None, None

    user_key = entry.get("id")
    record_key_hex = entry.get("record_key")
    record_key: Optional[bytes] = None
    if isinstance(record_key_hex, str):
        try:
            record_key = bytes.fromhex(record_key_hex)
        except ValueError:
            record_key = None

    if isinstance(user_key, str) and record_key is not None:
        return user_key, record_key

    return None, None


def get_user_storage_key(admin: AdminUser, username: str) -> Optional[str]:
    user_key, _ = _parse_user_index_entry(getattr(admin, "user_keys", {}).get(username))
    return user_key


def get_user_record_key(admin: AdminUser, username: str) -> Optional[bytes]:
    _, record_key = _parse_user_index_entry(
        getattr(admin, "user_keys", {}).get(username)
    )
    return record_key


def verify_user_password(user_dict: UserDict, password: str) -> bool:
    salt_hex = user_dict.get("auth_salt")
    verifier_hex = user_dict.get("auth_verifier")
    if isinstance(salt_hex, str) and isinstance(verifier_hex, str):
        return verify_password(password, salt_hex, verifier_hex)

    return False


# --------------------
# Admin Utilities
# --------------------


def get_admin_record() -> Optional[AdminUser]:
    """Return the AdminUser object if exists."""
    admin_key = get_admin_key()
    raw = _read_record_bytes(_user_file_path(admin_key))
    data = _deserialize_user_record(raw, _derive_admin_record_key(admin_key))
    if data is None:
        return None

    admin_payload = {
        "username": data.get("username", ADMIN),
        "file_keys": data.get("file_keys", {}),
        "group_keys": data.get("group_keys", {}),
        "user_keys": data.get("user_keys", {}),
    }
    return AdminUser(**admin_payload)


def _get_admin_or_fail(admin: Optional[AdminUser] = None) -> Optional[AdminUser]:
    admin = admin or get_admin_record()
    if not admin:
        print("Admin record not found.")
    return admin


def add_user_key_to_admin(
    username: str,
    user_key: str,
    record_key_hex: str,
    admin: Optional[AdminUser] = None,
) -> Optional[AdminUser]:
    admin = _get_admin_or_fail(admin)
    if not admin:
        return None

    if getattr(admin, "user_keys", None) is None:
        admin.user_keys = {}

    admin.user_keys[username] = {"id": user_key, "record_key": record_key_hex}
    save_admin_record(admin.__dict__)
    return admin


# --------------------
# User Storage
# --------------------


def save_user(user_key: str, user_dict: UserDict, record_key: bytes) -> None:
    """Save user record to disk (serialization hook supports future encryption)."""
    path = _user_file_path(user_key)
    payload = encrypt_with_key(json.dumps(user_dict).encode("utf-8"), record_key)
    path.write_bytes(payload)


def save_admin_record(admin_dict: UserDict) -> None:
    admin_key = get_admin_key()
    save_user(admin_key, admin_dict, record_key=_derive_admin_record_key(admin_key))


def _load_user_by_key(user_key: str, record_key: bytes) -> Optional[UserDict]:
    raw = _read_record_bytes(_user_file_path(user_key))
    return _deserialize_user_record(raw, record_key)


def load_user(username: str, admin: Optional[AdminUser] = None) -> Optional[UserDict]:
    """Load user by username using strict admin index entry (id + record_key)."""
    admin = admin or get_admin_record()
    if not admin or not getattr(admin, "user_keys", None):
        return None

    user_key = get_user_storage_key(admin, username)
    record_key = get_user_record_key(admin, username)
    if not user_key or not record_key:
        return None
    return _load_user_by_key(user_key, record_key)


def user_exists(username: str, admin: Optional[AdminUser] = None) -> bool:
    if admin and username in getattr(admin, "user_keys", {}):
        return True
    return load_user(username, admin=admin) is not None


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

    if is_admin and username == ADMIN:
        user_key = get_admin_key()
        record_key = _derive_admin_record_key(user_key)
    else:
        user_key = os.urandom(16).hex()
        record_key = os.urandom(32)

    user_dict: UserDict = {
        "username": username,
        "file_keys": {},
        "group_keys": [],
    }

    if is_admin:
        user_dict["user_keys"] = {}
        user_dict["group_keys"] = {}
    else:
        auth_salt, auth_verifier = create_password_to_verify(password)
        user_dict["auth_salt"] = auth_salt
        user_dict["auth_verifier"] = auth_verifier

    save_user(user_key, user_dict, record_key=record_key)
    admin = add_user_key_to_admin(
        username,
        user_key,
        record_key_hex=record_key.hex(),
        admin=admin,
    )

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
    user_key = get_user_storage_key(admin, username)
    if not user_key:
        print(f"User '{username}' not found.")
        return None, None

    user = load_user(username, admin=admin)
    if not user:
        print("User file not found.")
        return None, None

    return user_key, user
