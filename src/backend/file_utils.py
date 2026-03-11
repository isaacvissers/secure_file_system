from typing import Any

from backend.auth import _get_admin_or_fail, load_user, save_user
from backend.group_utils import get_user_groups_by_username, load_group, save_group

FILE_INDEX = "encrypted_name"

# --------------------
# File Management (simple, explicit)
# --------------------


def _normalize_file_key(file_key: Any) -> str:
    """Return a stable string identifier for a file key.

    Handles:
    - bytes/bytearray -> hex string
    - objects with `FILE_INDEX` or `metadata.FILE_INDEX` (use that)
    - fallback -> str(file_key)
    """
    # If the object exposes an encrypted field, prefer that.
    enc = getattr(file_key, FILE_INDEX, None)

    if isinstance(enc, (bytes, bytearray)):
        return enc.hex()
    if isinstance(enc, str):
        return enc

    # Directory-like object with metadata.encrypted_name
    metadata = getattr(file_key, "metadata", None)
    if metadata is not None:
        nested = getattr(metadata, FILE_INDEX, None)
        if isinstance(nested, (bytes, bytearray)):
            return nested.hex()
        if isinstance(nested, str):
            return nested

    # Raw bytes passed directly
    if isinstance(file_key, (bytes, bytearray)):
        return file_key.hex()

    # Strings remain as-is (likely already hex)
    if isinstance(file_key, str):
        return file_key

    # Fallback to generic string representation
    return str(file_key)


def get_user_file_keys(username: str) -> list:
    """Return the list of file keys associated with the user."""
    user = load_user(username)
    if not user:
        print(f"User '{username}' not found.")
        return []

    file_keys = user.get("file_keys", [])
    if isinstance(file_keys, dict):
        return list(file_keys.values())
    if isinstance(file_keys, list):
        return file_keys
    return [str(file_keys)]


def _infer_file_name(file_name_or_key: Any) -> str:
    """Return a stable mapping key for storing a user's file key."""
    path = getattr(file_name_or_key, "path", None)
    if path is not None:
        return str(path)

    metadata = getattr(file_name_or_key, "metadata", None)
    if metadata is not None:
        metadata_path = getattr(metadata, "path", None)
        if metadata_path is not None:
            return str(metadata_path)

    return _normalize_file_key(file_name_or_key)


def add_file_to_user(file_name: Any, file_key: Any = None, username: str = None) -> bool:
    """Normalize `file_key` and add it to the user's `file_keys` list."""
    if username is None:
        username = file_key
        file_key = file_name
        file_name = _infer_file_name(file_key)

    admin = _get_admin_or_fail()
    if not admin:
        return None

    user_key = getattr(admin, "user_keys", {}).get(username)
    if not user_key:
        print(f"User '{username}' not found.")
        return False

    user = load_user(username)
    if not user:
        print("User file not found.")
        return False

    if not isinstance(user.get("file_keys"), dict):
        user["file_keys"] = {}

    fk = _normalize_file_key(file_key)
    user["file_keys"][file_name] = fk
    save_user(user_key, user)

    return True


def add_file_to_group(group_name: str, file_key: Any) -> bool:
    """Normalize `file_key` and add it to the group's `file_keys` list."""
    admin = _get_admin_or_fail()
    if not admin:
        return None

    group_key = admin.group_keys.get(group_name)

    if not group_key:
        print(f"Group '{group_name}' not found.")
        return False

    group = load_group(group_name)
    if not group:
        print("Group file not found.")
        return False

    fk = _normalize_file_key(file_key)
    group.setdefault("file_access", [])
    if fk not in group["file_access"]:
        group["file_access"].append(fk)
        save_group(group_key, group)

    return True


def add_file_to_user_and_groups(file_key: Any, username: str) -> bool:
    """Add file to the user and to all groups the user belongs to."""
    if not add_file_to_user(file_key, username):
        return False

    if not get_user_groups_by_username(username):
        return True

    fk = _normalize_file_key(file_key)
    for g in get_user_groups_by_username(username) or []:
        add_file_to_group(g, fk)

    return True
