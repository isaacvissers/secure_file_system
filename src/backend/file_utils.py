import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from models.file import File
from models.group import Group
from models.user import User

FILE_INDEX = "encrypted_name"

# --------------------
# File Management (simple, explicit)
# --------------------


def _extract_file_info_name(value: Any) -> str | None:
    """Return decrypted display name from current or legacy `file_info` value shapes.

    Supported values:
    - str (current shape)
    - tuple/list with first element = name (legacy shape)
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (tuple, list)) and value:
        first = value[0]
        if isinstance(first, str):
            return first
    return None


def _normalize_file_info_map(file_info: Any) -> tuple[dict[str, str], bool]:
    """Normalize `file_info` values to names-only mapping.

    Returns `(normalized_map, changed)` where `changed` indicates whether any
    value shape differed from the normalized representation.
    """
    if not isinstance(file_info, dict):
        return {}, True

    normalized: dict[str, str] = {}
    changed = False
    for key, value in file_info.items():
        name = _extract_file_info_name(value)
        if name is not None:
            normalized[str(key)] = name
        if not (isinstance(value, str) and value == name):
            changed = True

    return normalized, changed


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


def add_file_to_user(
    file_name: Any,
    user: User,
    file_key: Any = None,
    user_file_key: bytes | None = None,
) -> bool:
    """
    Normalize `file_key` and add it to the user's `file_keys` list.
    Also add additional file information to user file.
    """
    normalized_file_info, _ = _normalize_file_info_map(user.file_info)
    user.file_info = normalized_file_info

    # add file_key
    fk = _normalize_file_key(file_key)
    user.file_keys[file_name] = fk

    # add file_info
    # `file_key` may be raw bytes (e.g., File.create path), so resolve path
    # from either `file_name` or object attributes.
    tracked_path = getattr(file_key, "path", None)
    if tracked_path is None and isinstance(file_name, str):
        tracked_path = Path(file_name)

    if tracked_path is None:
        metadata = getattr(file_key, "metadata", None)
        tracked_path = getattr(metadata, "path", None)

    if isinstance(tracked_path, str):
        tracked_path = Path(tracked_path)

    file = None
    if isinstance(tracked_path, Path):
        file = try_decrypt_file(tracked_path, fk)
        if file is None:
            file = try_decrypt_directory(tracked_path, fk)

    if file and file.path.exists():
        hashes = _read_integrity_hashes(file.path)
        if hashes:
            user.file_info[file_name] = file.file_name

    save_key = user_file_key or getattr(user, "_encryption_key", None)
    if not save_key:
        raise ValueError("Missing user file key when saving metadata")
    user.save(save_key)

    return True


def add_file_to_group(group: Group, group_key: str, file: File, file_key: Any) -> bool:
    """Normalize `file_key` and add it to the group's `file_keys` list."""
    fk = _normalize_file_key(file_key)
    file_id = str(file.path)
    group.file_access[file_id] = {
        "path": file_id,
        "key": fk if isinstance(fk, str) else fk.hex(),
        "name": file.file_name,
        "owner": file.owner_name,
    }
    group.save(group_key)

    return True


def _read_integrity_hashes(path: Path) -> tuple[str, str] | None:
    """Return (computed_hash, stored_hash) for the file, or None if unreadable/malformed.

    Both values are lowercase SHA-256 hex strings. A valid file satisfies
    computed_hash == stored_hash. Callers may also compare stored_hash against
    a known-good baseline to detect silent content replacement.
    """
    if not path.exists():
        return None

    content = path.read_bytes()
    if len(content) < 64:
        return None

    try:
        stored = content[-64:].decode("utf-8")
    except UnicodeDecodeError:
        return None

    if len(stored) != 64:
        return None

    return hashlib.sha256(content[:-64]).hexdigest(), stored


def sync_file_info_for_user(user: User, file: File) -> bool:
    """Refresh a single `file_info` entry from on-disk encrypted content."""
    # Silent lookup: File.save may call this in test fixtures that intentionally
    # don't create an admin record, and this should not print to stdout.
    normalized_file_info, _ = _normalize_file_info_map(user.file_info)
    user.file_info = normalized_file_info

    path_obj = file.path
    path_key = str(path_obj)

    file_key_hex = (
        _normalize_file_key(file.encrypted_file_key)
        if file.encrypted_file_key is not None
        else None
    )
    if not file_key_hex:
        file_key_hex = (user.file_keys or {}).get(path_key)
    if not file_key_hex:
        return False

    file = try_decrypt_file(path_obj, file_key_hex)
    if file is None:
        file = try_decrypt_directory(path_obj, file_key_hex)
    if file is None:
        return False

    user.file_info[path_key] = file.file_name
    save_key = getattr(user, "_encryption_key", None)
    if not save_key:
        raise ValueError("Missing user file key when saving metadata")
    user.save(save_key)
    return True


def remove_file_tracking_for_user(user: User, tracked_path: str | Path) -> bool:
    """Remove stale file tracking for a path from both `file_keys` and `file_info`."""
    path_key = str(
        tracked_path if isinstance(tracked_path, Path) else Path(tracked_path)
    )

    changed = False
    if isinstance(user.file_keys, dict) and path_key in user.file_keys:
        user.file_keys.pop(path_key, None)
        changed = True

    if isinstance(user.file_info, dict) and path_key in user.file_info:
        user.file_info.pop(path_key, None)
        changed = True

    if changed:
        save_key = getattr(user, "_encryption_key", None)
        if not save_key:
            raise ValueError("Missing user file key when saving metadata")
        user.save(save_key)
    return changed


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
            match = re.search(
                r'"file_name"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', tentative_text
            )
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
    file_info: dict | None = None,
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
            # Prefer file_info: works even when the metadata file is unreadable/corrupted.
            info = (file_info or {}).get(str(metadata_path))
            info_name = _extract_file_info_name(info)
            if info_name:
                displayed_parts.append(info_name)
            else:
                metadata_key_hex = file_keys.get(str(metadata_path))
                decrypted_name = _decrypted_display_for_path(
                    metadata_path, metadata_key_hex
                )
                displayed_parts.append(decrypted_name or part)
            current_dir = part_path
            continue

        # Last component: prefer file_info for the display name.
        info = (file_info or {}).get(str(path))
        info_name = _extract_file_info_name(info)
        if info_name:
            displayed_parts.append(info_name)
        else:
            file_key_hex = file_keys.get(str(path))
            decrypted_leaf = _decrypted_display_for_path(path, file_key_hex)
            displayed_parts.append(decrypted_leaf or part)

    return f"{username}/" + "/".join(displayed_parts)


def check_user_file_integrities(current_user: dict, user_home: Path) -> list[str]:
    """Return compromised owned paths as username-prefixed, display-ready strings."""
    user_metadata = current_user
    username = current_user.username
    file_keys = current_user.file_keys
    file_info = current_user.file_info
    if not isinstance(file_keys, dict):
        return []
    normalized_file_info, _ = _normalize_file_info_map(file_info)
    file_info = normalized_file_info

    compromised_paths: set[Path] = set()

    for path_str, file_key_hex in file_keys.items():
        tracked_path = Path(path_str)
        if not tracked_path.is_relative_to(user_home):
            continue

        if not tracked_path.exists():
            compromised_paths.add(tracked_path)
            continue

        hashes = _read_integrity_hashes(tracked_path)
        if hashes is None or hashes[0] != hashes[1]:
            # Unreadable, too short, or internally inconsistent.
            compromised_paths.add(tracked_path)
            continue

        # Integrity validation is based solely on the embedded trailing hash.
        # No separate hash baseline is stored in `file_info`.

    display_paths = [
        _build_compromised_display_path(path, user_home, username, file_keys, file_info)
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
