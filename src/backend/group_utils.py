import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from backend.cryptography_utils import decrypt_with_key, encrypt_with_key

if TYPE_CHECKING:
    from models.user import AdminUser

SRC_DIR = Path(__file__).resolve().parents[1]
GROUPS_DIR = SRC_DIR / "storage/.groups"
GROUPS_DIR.mkdir(parents=True, exist_ok=True)

GroupsDict = Dict[str, Any]


# --------------------
# Key Utilities
# --------------------
def create_group_file_name() -> str:
    """Generate a random storage file name for a group record."""
    return os.urandom(16).hex()


def create_group_encryption_key() -> bytes:
    """Generate a random 32-byte key for group record encryption."""
    return os.urandom(32)


def _parse_group_index_entry(entry: Any) -> tuple[Optional[str], Optional[bytes]]:
    """Parse a group index entry into (file_path, encryption_key bytes)."""
    if not isinstance(entry, dict):
        return None, None

    file_path = entry.get("file_path")
    encryption_key_hex = entry.get("encryption_key")
    encryption_key: Optional[bytes] = None
    if isinstance(encryption_key_hex, str):
        try:
            encryption_key = bytes.fromhex(encryption_key_hex)
        except ValueError:
            encryption_key = None

    if isinstance(file_path, str) and encryption_key is not None:
        return file_path, encryption_key

    return None, None


def get_group_access(
    admin: "AdminUser", group_name: str
) -> tuple[Optional[str], Optional[bytes]]:
    """Return a group's (file_path, encryption_key) from admin metadata."""
    return _parse_group_index_entry(getattr(admin, "group_keys", {}).get(group_name))


def get_user_group_access(
    user: Dict[str, Any], group_name: str
) -> tuple[Optional[str], Optional[bytes]]:
    """Return a user's cached group (file_path, encryption_key) metadata."""
    group_keys = user.get("group_keys", {})
    if not isinstance(group_keys, dict):
        return None, None
    entry = group_keys.get(group_name)
    if not isinstance(entry, dict):
        return None, None
    return _parse_group_index_entry(entry)


# --------------------
# File Utilities
# --------------------


def _read_record_bytes(path: Path) -> Optional[bytes]:
    """Read raw bytes from disk, returning None if unavailable."""
    if not path.exists():
        return None
    try:
        return path.read_bytes()
    except Exception:
        return None


def _write_record_bytes(path: Path, payload: bytes) -> None:
    """Write raw bytes payload to disk."""
    path.write_bytes(payload)


def _serialize_group_record(group_dict: GroupsDict, record_key: bytes) -> bytes:
    """Serialize and encrypt a group dictionary."""
    return encrypt_with_key(json.dumps(group_dict).encode("utf-8"), record_key)


def _deserialize_group_record(
    record: Optional[bytes], record_key: bytes
) -> Optional[GroupsDict]:
    """Decrypt and deserialize group bytes into a dictionary."""
    if record is None:
        return None
    try:
        decrypted = decrypt_with_key(record, record_key)
        data = json.loads(decrypted.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _auth_module():
    """Import and return the auth module."""
    import backend.auth as auth

    return auth


def _get_auth_and_admin(admin: Optional["AdminUser"] = None):
    """Return (auth_module, admin_record), resolving admin if needed."""
    auth = _auth_module()
    resolved_admin = admin or auth.get_admin_record()
    return auth, resolved_admin


def _require_group_access(
    admin: "AdminUser", group_name: str
) -> tuple[Optional[str], Optional[bytes]]:
    """Resolve required group path/key, printing an error on failure."""
    group_path, group_record_key = get_group_access(admin, group_name)
    if not group_path or not group_record_key:
        print(f"Group '{group_name}' not found.")
        return None, None
    return group_path, group_record_key


def _require_group_context(
    admin: "AdminUser", group_name: str
) -> tuple[Optional[str], Optional[bytes], Optional[GroupsDict]]:
    """Resolve group path/key and loaded group dict, or Nones on failure."""
    group_path, group_record_key = _require_group_access(admin, group_name)
    if not group_path or not group_record_key:
        return None, None, None

    group = load_group(group_name, admin=admin)
    if not group:
        print("Group file not found.")
        return None, None, None

    return group_path, group_record_key, group


def _require_user_context(auth, admin: "AdminUser", username: str):
    """Resolve user key, user dict, and user record key, or Nones on failure."""
    user_key = auth.get_user_storage_key(admin, username)
    if not user_key:
        print(f"User '{username}' not found.")
        return None, None, None

    user = auth.load_user(username, admin=admin)
    if not user:
        print("User file not found.")
        return None, None, None

    user_record_key = auth.get_user_record_key(admin, username)
    if not user_record_key:
        print("User key metadata missing.")
        return None, None, None

    return user_key, user, user_record_key


def load_group(name: str, admin: Optional["AdminUser"] = None) -> Optional[GroupsDict]:
    """Load and decrypt a group record by group name."""
    _auth, admin = _get_auth_and_admin(admin)
    if not admin:
        return None

    group_path, record_key = get_group_access(admin, name)
    if not group_path or not record_key:
        return None

    raw = _read_record_bytes(Path(group_path))
    return _deserialize_group_record(raw, record_key)


def save_group(group_path: str, group_dict: GroupsDict, record_key: bytes) -> None:
    """Encrypt and persist a group record to its storage path."""
    payload = _serialize_group_record(group_dict, record_key)
    _write_record_bytes(Path(group_path), payload)


# --------------------
# Group Creation
# --------------------


def create_group(
    name: str, admin: Optional["AdminUser"] = None
) -> Optional[GroupsDict]:
    """Create a new encrypted group record and index it in admin metadata."""
    auth, admin = _get_auth_and_admin(admin)
    if not admin:
        print("Admin record not found.")
        return None

    if name in admin.group_keys:
        print(f"Group '{name}' already exists.")
        return None

    group_file_name = create_group_file_name()
    group_record_key = create_group_encryption_key()

    group = {
        "group_name": name,
        "members": {},
        "file_access": [],
    }

    group_path = str(GROUPS_DIR / f"{group_file_name}.json")
    save_group(group_path, group, record_key=group_record_key)

    admin.group_keys[name] = {
        "file_path": group_path,
        "encryption_key": group_record_key.hex(),
    }
    auth.save_admin_record(admin.__dict__)

    return group


# --------------------
# User Management
# --------------------


def get_user_groups_by_username(
    username: str,
    admin: Optional["AdminUser"] = None,
) -> List[str]:
    """Return group names with valid metadata for the given user."""
    auth, admin = _get_auth_and_admin(admin)
    if not admin:
        print("Admin record not found.")
        return []
    _user_key, user, _user_record_key = _require_user_context(auth, admin, username)
    if not user:
        return []

    user_gkeys = user.get("group_keys", {})
    if not isinstance(user_gkeys, dict) or not user_gkeys:
        return []

    return [
        group_name
        for group_name in user_gkeys
        if isinstance(group_name, str) and all(get_user_group_access(user, group_name))
    ]


def add_user_to_group(
    group_name: str,
    username: str,
    admin: Optional["AdminUser"] = None,
) -> bool:
    """Add a user to a group and update both encrypted records."""
    auth, admin = _get_auth_and_admin(admin)
    if not admin:
        print("Admin record not found.")
        return False

    group_path, group_record_key, group = _require_group_context(admin, group_name)
    if not group_path or not group_record_key or not group:
        return False

    user_key, user, user_record_key = _require_user_context(auth, admin, username)
    if not user_key or not user or not user_record_key:
        return False

    if not _add_member_to_group(group, username, user_key):
        return False

    _add_group_to_user(user, group_name, group_path, group_record_key)

    save_group(group_path, group, record_key=group_record_key)
    auth.save_user(user_key, user, record_key=user_record_key)

    return True


def remove_user_from_group(
    group_name: str,
    username: str,
    admin: Optional["AdminUser"] = None,
) -> bool:
    """Remove a user from a group and update both encrypted records."""
    auth, admin = _get_auth_and_admin(admin)
    if not admin:
        print("Admin record not found.")
        return False

    group_path, group_record_key, group = _require_group_context(admin, group_name)
    if not group_path or not group_record_key or not group:
        return False

    user_key, user, user_record_key = _require_user_context(auth, admin, username)
    if not user_key or not user or not user_record_key:
        return False

    members = group.setdefault("members", {})
    if user_key not in members:
        print("User is not a member of the group.")
        return False

    # remove member from group
    members.pop(user_key, None)

    gkeys = user.setdefault("group_keys", {})
    if isinstance(gkeys, dict):
        gkeys.pop(group_name, None)
    else:
        user["group_keys"] = {}

    save_group(group_path, group, record_key=group_record_key)
    auth.save_user(user_key, user, record_key=user_record_key)

    return True


# --------------------
# Helpers
# --------------------


def _add_member_to_group(group: dict, username: str, user_key: str) -> bool:
    """Insert user membership into a group if not already present."""
    members = group.setdefault("members", {})

    if user_key in members:
        print("User already in group.")
        return False

    members[user_key] = username
    return True


def _add_group_to_user(
    user: dict, group_name: str, group_path: str, group_record_key: bytes
):
    """Store group access metadata inside a user's group_keys mapping."""
    group_keys = user.setdefault("group_keys", {})
    if not isinstance(group_keys, dict):
        group_keys = {}
        user["group_keys"] = group_keys

    group_keys[group_name] = {
        "file_path": group_path,
        "encryption_key": group_record_key.hex(),
    }
