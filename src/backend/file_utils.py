import hashlib
import json
import re
from typing import Any

from backend.auth import _get_admin_or_fail, load_user, save_user
from backend.group_utils import get_user_groups_by_username, load_group, save_group
from models.file import File
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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


def add_file_to_user(
    file_name: Any, file_key: Any = None, username: str = None
) -> bool:
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
        return False

    user = load_user(username)
    if not user:
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

def _has_valid_encrypted_integrity(path: Path) -> bool:
    """Return True when the on-disk integrity hash matches encrypted payload bytes."""
    content = path.read_bytes()
    if len(content) < 64:
        return False

    payload = content[:-64]
    try:
        stored_hash = content[-64:].decode("utf-8")
    except UnicodeDecodeError:
        return False

    if len(stored_hash) != 64:
        return False

    computed_hash = hashlib.sha256(payload).hexdigest()
    return stored_hash == computed_hash


def _decrypted_display_for_path(path: Path, file_key_hex: str | None) -> str | None:
    """Return decrypted logical name for a tracked path when possible."""
    if path.name.startswith(".") and (path.parent / path.name[1:]).is_dir():
        decrypted = try_decrypt_directory(path, file_key_hex)
        if decrypted:
            return decrypted.file_name.lstrip(".")
        recovered = _recover_file_name_unverified(path, file_key_hex)
        if recovered:
            return recovered.lstrip(".")
        return None

    decrypted = try_decrypt_file(path, file_key_hex)
    if decrypted:
        return decrypted.file_name
    recovered = _recover_file_name_unverified(path, file_key_hex)
    if recovered:
        return recovered
    return None


def _recover_file_name_unverified(path: Path, file_key_hex: str | None) -> str | None:
    """Best-effort file-name recovery when authenticated decrypt fails.

    This is intentionally used only for warning display. If GCM tag verification
    fails, plaintext authenticity is not guaranteed; we do not trust recovered
    content for authorization, writes, or policy decisions.
    """
    if not file_key_hex:
        return None

    try:
        file_key = bytes.fromhex(file_key_hex)
    except ValueError:
        return None

    if not path.exists():
        return None

    payload = path.read_bytes()
    if len(payload) < (12 + 16 + 64):
        return None

    nonce = payload[:12]
    encrypted_blob = payload[12:-64]
    if len(encrypted_blob) < 16:
        return None

    ciphertext = encrypted_blob[:-16]
    tag = encrypted_blob[-16:]

    try:
        decryptor = Cipher(algorithms.AES(file_key), modes.GCM(nonce, tag)).decryptor()
        # Read tentative plaintext bytes first; this can still be useful for
        # forensic display even if `finalize()` later raises InvalidTag.
        tentative_plaintext = decryptor.update(ciphertext)
        try:
            decryptor.finalize()
        except InvalidTag:
            pass

        tentative_text = tentative_plaintext.decode("utf-8", errors="ignore")

        # Preferred path: parse the full JSON blob when corruption is limited
        # to authenticated tag/hash bytes and payload remains structurally valid.
        try:
            data = json.loads(tentative_text)
            file_name = data.get("file_name")
            if isinstance(file_name, str) and file_name:
                return file_name
        except Exception:
            # Fallback path: if JSON is partially corrupted, salvage only the
            # file_name field for display by scanning decoded plaintext.
            match = re.search(r'"file_name"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', tentative_text)
            if match:
                raw = match.group(1)
                try:
                    # Reuse JSON string unescaping rules so escaped characters
                    # (if present) are interpreted consistently.
                    recovered_name = json.loads(f'"{raw}"')
                    if isinstance(recovered_name, str) and recovered_name:
                        return recovered_name
                except Exception:
                    if raw:
                        return raw
    except Exception:
        return None

    return None


def _build_compromised_display_path(
    path: Path,
    user_home: Path,
    username: str,
    file_keys: dict[str, str],
) -> str:
    """Render `username/...` with decrypted names where available, else encrypted path segments."""
    try:
        relative_path = path.relative_to(user_home)
    except ValueError:
        return f"{username}/{path.name}"

    if not relative_path.parts:
        return username

    current_dir = user_home
    displayed_parts: list[str] = []
    total_parts = len(relative_path.parts)

    for index, part in enumerate(relative_path.parts):
        is_last = index == (total_parts - 1)
        part_path = current_dir / part

        if not is_last:
            metadata_path = current_dir / f".{part}"
            metadata_key_hex = file_keys.get(str(metadata_path))
            decrypted_name = _decrypted_display_for_path(metadata_path, metadata_key_hex)
            displayed_parts.append(decrypted_name or part)
            current_dir = part_path
            continue

        # Last component can be a file, or a directory metadata file.
        file_key_hex = file_keys.get(str(path))
        decrypted_leaf = _decrypted_display_for_path(path, file_key_hex)
        displayed_parts.append(decrypted_leaf or part)

    return f"{username}/" + "/".join(displayed_parts)


def check_user_file_integrities(current_user: dict, user_home: Path) -> list[str]:
    """Return compromised owned paths as username-prefixed, display-ready strings."""
    username = current_user.get("username", "user")
    file_keys = current_user.get("file_keys", {}) or {}
    if not isinstance(file_keys, dict):
        return []

    compromised_paths: set[Path] = set()

    for path_str, file_key_hex in file_keys.items():
        tracked_path = Path(path_str)
        if not tracked_path.is_relative_to(user_home):
            continue

        if not tracked_path.exists():
            compromised_paths.add(tracked_path)
            continue

        if not _has_valid_encrypted_integrity(tracked_path):
            compromised_paths.add(tracked_path)
            continue

        if _decrypted_display_for_path(tracked_path, file_key_hex) is None:
            compromised_paths.add(tracked_path)

    display_paths = [
        _build_compromised_display_path(path, user_home, username, file_keys)
        for path in compromised_paths
    ]
    return sorted(set(display_paths))

def try_decrypt_file(entry: Path, file_key_hex: str | None) -> File | None:
    if file_key_hex:
        try:
            file_key = bytes.fromhex(file_key_hex)
            file = File.get_file(entry, file_key)
            return file
        except Exception:
            return None

    return None

def try_decrypt_directory(metadata_path: Path, file_key_hex: str | None) -> File | None:
    if file_key_hex:
        try:
            file_key = bytes.fromhex(file_key_hex)
            metadata_file = File.get_file(metadata_path, file_key)
            return metadata_file
        except Exception:
            return None

    return None