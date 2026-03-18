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
    admin_path = _user_file_path(get_admin_key())

    if not admin_path.exists():
        admin_user, admin_key = AdminUser.create(username, password)
        return admin_user, admin_key, "created"

    return None, None, "exists"


def ensure_group(name: str):
    """Ensure a group exists and return ('created' | 'exists' | 'missing')."""
    encrypted_name = hashlib.sha256(name.encode("utf-8")).hexdigest()
    group_path = GROUPS_DIR / encrypted_name

    if group_path.exists():
        return None, None, "exists"

    all_group, master_key = Group.create(name)
    if all_group is None:
        return None, None, "missing"

    return all_group, master_key, "created"


def main() -> None:
    print(f"Storage directory: {STORAGE_DIR}")

    admin_user, admin_key, status = ensure_admin_user(ADMIN, ADMIN)
    if status in {"created", "updated"}:
        print(f"Admin user {status}: {ADMIN}")
    elif status == "exists":
        print(f"Admin user already exists: {ADMIN}")
    else:
        print("Admin user record missing or corrupted.")

    all_group, group_master_key, group_status = ensure_group("all")
    if group_status == "created":
        print("Group created: all")
        if admin_user is not None and group_master_key:
            key_material = (
                admin_key if isinstance(admin_key, bytes) else admin_key.encode()
            )
            add_group_to_user(admin_user, all_group, group_master_key, key_material)
            admin_user.save(key_material)
    elif group_status == "exists":
        print("Group already exists: all")
    else:
        print("Group record missing or could not be created: all")


if __name__ == "__main__":
    main()
