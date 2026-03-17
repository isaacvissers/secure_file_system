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
    groups = []

    if not user.group_keys:
        return groups

    for group_path_str in user.group_keys.keys():
        group_path = Path(group_path_str)
        if group_path.exists():
            try:
                group_obj = Group.get_group(group_path)
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


def add_user_to_group(user, group: Group) -> bool:
    """Add a user to the group's member list."""
    group.members[user.get_encrypted_name()] = user.username
    group.save()
    return True


def add_group_to_user(user: User | AdminUser, group: Group, master_key: str) -> bool:
    """Store group access metadata inside a user's group_keys mapping."""
    group_id = str(group.path)
    user.group_keys[group.group_name] = {
        "id": group_id,  # the ACTUAL path to the group
        "key": master_key,  # AES key for the group
    }

    user.save()
    return True


def remove_user_from_group(user: User | AdminUser, group: Group) -> bool:
    """Remove a user's access from the group's member list."""
    if user.get_encrypted_name() in group.members:
        del group.members[user.get_encrypted_name()]
        group.save()
        return True
    else:
        print(f"User {user.username} not found in group {group.group_name}.")
        return False


def remove_group_from_user(user: User | AdminUser, group: Group) -> bool:
    """Remove group access metadata (path and key) from the user's mapping."""
    group_id = str(group.path)

    if user.group_keys and group_id in user.group_keys:
        del user.group_keys[group_id]
        user.save()
        return True
    else:
        print(f"Group key for {group.group_name} not found in user's profile.")
        return False
