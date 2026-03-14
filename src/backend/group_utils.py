import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from models.user import AdminUser

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


def _serialize_group_record(group_key: str, group_dict: GroupsDict) -> Dict[str, Any]:
    """Serialization hook for group records (future: encrypt here)."""
    _ = group_key
    return group_dict


def _deserialize_group_record(
    group_key: str, record: Optional[Dict[str, Any]]
) -> Optional[GroupsDict]:
    """Deserialization hook for group records (future: decrypt here)."""
    _ = group_key
    if not isinstance(record, dict):
        return None
    return record


def _load_group_by_key(group_key: str) -> Optional[GroupsDict]:
    raw = _read_json(_group_file(group_key))
    return _deserialize_group_record(group_key, raw)


def _auth_module():
    import backend.auth as auth

    return auth


def _save_admin_group_index(admin: "AdminUser") -> None:
    auth = _auth_module()
    auth.save_user(auth.get_admin_key(), admin.__dict__)


def load_group(name: str, admin: Optional["AdminUser"] = None) -> Optional[GroupsDict]:
    auth = _auth_module()
    admin = admin or auth.get_admin_record()
    if not admin:
        return None

    group_key = admin.group_keys.get(name)
    if not group_key:
        return None

    return _load_group_by_key(group_key)


def save_group(group_key: str, group_dict: GroupsDict) -> None:
    payload = _serialize_group_record(group_key, group_dict)
    _write_json(_group_file(group_key), payload)


# --------------------
# Group Creation
# --------------------


def create_group(
    name: str, admin: Optional["AdminUser"] = None
) -> Optional[GroupsDict]:
    auth = _auth_module()
    admin = admin or auth.get_admin_record()
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
    _save_admin_group_index(admin)

    return group


# --------------------
# User Management
# --------------------


def get_user_groups_by_username(
    username: str,
    admin: Optional["AdminUser"] = None,
) -> List[str]:
    auth = _auth_module()
    admin = admin or auth.get_admin_record()
    if not admin:
        print("Admin record not found.")
        return []
    user_key = admin.user_keys.get(username)
    if not user_key:
        print(f"User '{username}' not found.")
        return []
    user = auth.load_user(username, admin=admin)
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


def add_user_to_group(
    group_name: str,
    username: str,
    admin: Optional["AdminUser"] = None,
) -> bool:
    auth = _auth_module()
    admin = admin or auth.get_admin_record()
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

    group = load_group(group_name, admin=admin)
    if not group:
        print("Group file not found.")
        return False

    user = auth.load_user(username, admin=admin)
    if not user:
        print("User file not found.")
        return False

    if not _add_member_to_group(group, username, user_key):
        return False

    _add_group_to_user(user, group_key)

    save_group(group_key, group)
    auth.save_user(user_key, user)

    return True


# --------------------
# Helpers
# --------------------


def _add_member_to_group(group: dict, username: str, user_key: str) -> bool:
    members = group.setdefault("members", {})

    if user_key in members:
        print("User already in group.")
        return False

    members[user_key] = username
    return True


def _add_group_to_user(user: dict, group_key: str):
    group_keys = user.setdefault("group_keys", [])

    if group_key not in group_keys:
        group_keys.append(group_key)


def remove_user_from_group(
    group_name: str,
    username: str,
    admin: Optional["AdminUser"] = None,
) -> bool:
    auth = _auth_module()
    admin = admin or auth.get_admin_record()
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

    group = load_group(group_name, admin=admin)
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
    user = auth.load_user(username, admin=admin)
    if user is None:
        print("User file not found.")
        return False

    gkeys = user.setdefault("group_keys", [])
    if group_key in gkeys:
        gkeys.remove(group_key)

    save_group(group_key, group)
    auth.save_user(user_key, user)

    return True
