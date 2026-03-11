import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import backend.auth as auth

SRC_DIR = Path(__file__).resolve().parents[1]
GROUPS_DIR = SRC_DIR / "storage/.groups"
GROUPS_DIR.mkdir(parents=True, exist_ok=True)

GroupsDict = Dict[str, Any]


# --------------------
# Key Utilities
# --------------------


def create_group_key(name: str) -> str:
    return f"group_{name}"


# --------------------
# File Utilities
# --------------------


def _group_file(group_key: str) -> Path:
    return GROUPS_DIR / f"{group_key}.json"


def load_group(name: str) -> Optional[GroupsDict]:
    admin = auth.get_admin_record()
    if not admin:
        return None

    group_key = admin.group_keys.get(name)
    if not group_key:
        return None

    path = _group_file(group_key)
    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_group(group_key: str, group_dict: GroupsDict) -> None:
    path = _group_file(group_key)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(group_dict, f)


# --------------------
# Group Creation
# --------------------


def create_group(name: str) -> Optional[GroupsDict]:
    admin = auth.get_admin_record()
    if not admin:
        print("Admin record not found.")
        return None

    if name in admin.group_keys:
        print(f"Group '{name}' already exists.")
        return None

    group_key = create_group_key(name)

    group = {
        "group_name": name,
        "members": {},
        "file_access": [],
    }

    save_group(group_key, group)

    admin.group_keys[name] = group_key
    auth.save_user(auth.get_admin_key(), admin.__dict__)

    return group


# --------------------
# User Management
# --------------------


def get_user_groups_by_username(username: str) -> List[str]:
    admin = auth.get_admin_record()
    if not admin:
        print("Admin record not found.")
        return []
    user_key = admin.user_keys.get(username)
    if not user_key:
        print(f"User '{username}' not found.")
        return []
    user = auth.load_user(username)
    if not user:
        print("User file not found.")
        return []
    # Stored in the user record are group storage keys (e.g. 'group_p').
    # Convert those to group names using the admin index so callers get
    # human-readable group names.
    user_gkeys = user.get("group_keys", [])
    if not user_gkeys:
        return []

    # build reverse mapping group_key -> group_name
    rev = {v: k for k, v in (admin.group_keys or {}).items()}
    result: List[str] = []
    for gk in user_gkeys:
        name = rev.get(gk)
        if name:
            result.append(name)
    return result


def add_user_to_group(group_name: str, username: str) -> bool:
    admin = auth.get_admin_record()
    if not admin:
        print("Admin record not found.")
        return False

    group_key = admin.group_keys.get(group_name)
    if not group_key:
        print(f"Group '{group_name}' not found.")
        return False

    user_key = admin.user_keys.get(username)
    if not user_key:
        print(f"User '{username}' not found.")
        return False

    group = load_group(group_name)
    if not group:
        print("Group file not found.")
        return False

    user = auth.load_user(username)
    if not user:
        print("User file not found.")
        return False

    if not _add_member_to_group(group, username, user_key):
        return False

    _add_group_to_user(user, group_key)

    # When a user is added to a group, also grant the group access to
    # all files the user already owns. User records store normalized
    # `file_keys`, so we can copy them directly into the group's
    # `file_access` list without importing `file_utils` (avoids cycles).
    user_file_keys = user.get("file_keys", [])
    if user_file_keys:
        fa = group.setdefault("file_access", [])
        for fk in user_file_keys:
            if fk not in fa:
                fa.append(fk)

    save_group(group_key, group)
    auth.save_user(user_key, user)

    return True


# --------------------
# Helpers
# --------------------


def _add_member_to_group(group: dict, username: str, user_key: str) -> bool:
    members = group.setdefault("members", {})

    if username in members:
        print("User already in group.")
        return False

    members[username] = user_key
    return True


def _add_group_to_user(user: dict, group_key: str):
    group_keys = user.setdefault("group_keys", [])

    if group_key not in group_keys:
        group_keys.append(group_key)


def remove_user_from_group(group_name: str, username: str) -> bool:
    admin = auth.get_admin_record()
    if not admin:
        print("Admin record not found.")
        return False

    group_key = admin.group_keys.get(group_name)
    if not group_key:
        print(f"Group '{group_name}' not found.")
        return False

    user_key = admin.user_keys.get(username)
    if not user_key:
        print(f"User '{username}' not found.")
        return False

    group = load_group(group_name)
    if not group:
        print("Group file not found.")
        return False

    members = group.setdefault("members", {})
    if username not in members:
        print("User is not a member of the group.")
        return False

    # remove member from group
    members.pop(username, None)

    # remove group from user's group_keys
    user = auth.load_user(username)
    if user is None:
        print("User file not found.")
        return False

    gkeys = user.setdefault("group_keys", [])
    if group_key in gkeys:
        gkeys.remove(group_key)

    save_group(group_key, group)
    auth.save_user(user_key, user)

    return True
