from pathlib import Path
from typing import Any

from backend.auth import _get_admin_or_fail, get_admin_record, load_user, save_user

# --------------------
# File Management
# --------------------


def add_file_to_user(file_key: Any, username: str) -> bool:
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

    # Normalize identifier
    fk: str
    # File-like object with encrypted_name attribute
    if hasattr(file_key, "encrypted_name"):
        enc = getattr(file_key, "encrypted_name")
        if isinstance(enc, (bytes, bytearray)):
            fk = enc.hex()
        else:
            fk = str(enc)
    # Directory-like object with metadata.encrypted_name
    elif hasattr(file_key, "metadata") and hasattr(file_key.metadata, "encrypted_name"):
        enc = getattr(file_key.metadata, "encrypted_name")
        if isinstance(enc, (bytes, bytearray)):
            fk = enc.hex()
        else:
            fk = str(enc)
    # raw encrypted bytes
    elif isinstance(file_key, (bytes, bytearray)):
        fk = file_key.hex()
    else:
        # fallback to string representation
        fk = str(file_key)

    file_keys = user.setdefault("file_keys", [])
    if fk not in file_keys:
        file_keys.append(fk)

    save_user(user_key, user)

    return True
