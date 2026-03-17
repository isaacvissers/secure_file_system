import hashlib
import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from backend.auth import ADMIN, STORAGE_DIR, _user_file_path, get_admin_key
from backend.group_utils import add_group_to_user
from models.group import GROUPS_DIR, Group
from models.user import AdminUser


def ensure_admin_user(username: str, password: str):
    """
    Ensure an admin user exists. If `reset_password` is True and an admin
    record exists, remove it and recreate the admin user.

    Returns a tuple of (admin_user, status) where status is
    'created', 'updated', 'exists', or 'missing'.
    """
    admin_path = _user_file_path(get_admin_key())

    if not admin_path.exists():
        admin_user, _ = AdminUser.create(username, password)
        return admin_user, "created"

    return admin_user, "exists"


def ensure_group(name: str):
    """Ensure a group exists and return ('created' | 'exists' | 'missing')."""
    encrypted_name = hashlib.sha256(name.encode("utf-8")).hexdigest()
    group_path = GROUPS_DIR / encrypted_name

    if group_path.exists():
        existing_group = Group.get_group(group_path)
        return existing_group, None, "exists"

    all_group, master_key = Group.create(name)
    if all_group is None:
        return None, None, "missing"

    return all_group, master_key, "created"


def main() -> None:
    print(f"Storage directory: {STORAGE_DIR}")

    admin_user, status = ensure_admin_user(ADMIN, ADMIN)
    if status in {"created", "updated"}:
        print(f"Admin user {status}: {ADMIN}")
    elif status == "exists":
        print(f"Admin user already exists: {ADMIN}")
    else:
        print("Admin user record missing or corrupted.")

    all_group, group_master_key, group_status = ensure_group("all")
    if group_status == "created":
        print("Group created: all")
    elif group_status == "exists":
        print("Group already exists: all")
    else:
        print("Group record missing or could not be created: all")
    if group_status == "created" and admin_user is not None and group_master_key:
        add_group_to_user(admin_user, all_group, group_master_key)


if __name__ == "__main__":
    main()
