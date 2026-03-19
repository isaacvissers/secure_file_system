import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.storage_paths import get_storage_dir
from models.group import Group
from models.user import AdminUser, User

GROUPS_DIR = get_storage_dir() / ".groups"
GROUPS_DIR.mkdir(parents=True, exist_ok=True)

GroupsDict = Dict[str, Any]


# --------------------
# User Management (Add/Remove User from Group)
# --------------------
def get_groups_by_user(user: User | AdminUser) -> List[Group]:
    """Retrieve all Group objects that the user has access to."""
    groups: List[Group] = []

    if not user.group_keys:
        return groups

    for group_name, group_info in user.group_keys.items():
        group_path = Path(group_info["id"])
        try:
            group_key = bytes.fromhex(group_info["key"])
        except Exception:
            print(f"Invalid key for group {group_name}")
            continue

        if group_path.exists():
            try:
                group_obj = Group.get_group(group_path, group_key)
                groups.append(group_obj)
            except Exception as e:
                print(f"Error loading group at {group_path}: {e}")

    return groups


def get_specific_group_for_user(
    user: User | AdminUser, target_name: str
) -> Optional[Group]:
    """Find a specific group by name from the user's allowed groups."""
    all_user_groups = get_groups_by_user(user)

    for group in all_user_groups:
        if group.group_name == target_name:
            return group

    return None


def add_user_to_group(
    user,
    group: Group,
    group_key: bytes,
    user_file_key: bytes | None = None,
) -> bool:
    """Add a user to the group's member list."""
    group.members[user.get_encrypted_name()] = user.username
    if user_file_key is not None:
        user.save(user_file_key)
    group.save(group_key)
    return True


def add_group_to_user(
    user: User | AdminUser,
    group: Group,
    master_key: bytes | str,
    user_file_key: bytes | None = None,
) -> bool:
    """Store group access metadata inside a user's group_keys mapping."""
    group_id = str(group.path)
    if isinstance(master_key, (bytes, bytearray)):
        key_hex = master_key.hex()
    else:
        key_hex = str(master_key)

    user.group_keys[group.group_name] = {
        "id": group_id,  # the ACTUAL path to the group
        "key": key_hex,  # AES key for the group
    }

    if user_file_key is not None:
        user.save(user_file_key)
    return True


def remove_user_from_group(
    user: User | AdminUser,
    group: Group,
    group_key: bytes,
    user_file_key: bytes | None = None,
) -> bool:
    """Remove a user's access from the group's member list."""
    if user.get_encrypted_name() in group.members:
        del group.members[user.get_encrypted_name()]
        if user_file_key is not None:
            user.save(user_file_key)
        group.save(group_key)
        return True
    else:
        print(f"User {user.username} not found in group {group.group_name}.")
        return False


def remove_group_from_user(
    user: User | AdminUser, group: Group, user_file_key: bytes | None = None
) -> bool:
    """Remove group access metadata (path and key) from the user's mapping."""
    if user.group_keys and group.group_name in user.group_keys:
        del user.group_keys[group.group_name]
        if user_file_key is not None:
            user.save(user_file_key)
        return True
    else:
        print(f"Group key for {group.group_name} not found in user's profile.")
        return False
