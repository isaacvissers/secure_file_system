import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from backend.auth import (
    ADMIN,
    _user_file_path,
    create_user,
    get_admin_key,
    get_admin_record,
)
from backend.group_utils import create_group, load_group


def ensure_admin_user(username: str, password: str, reset_password: bool = False):
    """
    Ensure an admin user exists. If `reset_password` is True and an admin
    record exists, remove it and recreate the admin user.

    Returns a tuple of (user_dict_or_admin_data, status) where status is
    'created', 'updated', 'exists', or 'missing'.
    """
    admin_path = _user_file_path(get_admin_key())

    if not admin_path.exists():
        # No admin file, create one
        new_user = create_user(username, password, is_admin=True)
        return new_user, "created"

    if reset_password:
        # Remove old admin record
        try:
            admin_path.unlink()
        except Exception as e:
            print(f"Warning: could not delete old admin record: {e}")
        new_user = create_user(username, password, is_admin=True)
        return new_user, "updated"

    # Admin file exists
    admin = get_admin_record()
    if admin is None:
        return None, "missing"

    return admin.__dict__, "exists"


def ensure_group(name: str):
    """Ensure a group exists and return ('created' | 'exists' | 'missing')."""
    existing = load_group(name)
    if existing is not None:
        return existing, "exists"

    created = create_group(name)
    if created is None:
        return None, "missing"

    return created, "created"


def main() -> None:
    admin_data, status = ensure_admin_user(ADMIN, ADMIN)
    if status in {"created", "updated"}:
        print(f"Admin user {status}: {ADMIN}")
    elif status == "exists":
        print(f"Admin user already exists: {ADMIN}")
    else:
        print("Admin user record missing or corrupted.")

    _, group_status = ensure_group("all")
    if group_status == "created":
        print("Group created: all")
    elif group_status == "exists":
        print("Group already exists: all")
    else:
        print("Group record missing or could not be created: all")


if __name__ == "__main__":
    main()
