from pathlib import Path

from models.file import File


def track_file(shell, file: File) -> File:
    """Register a file key in the shell's in-memory user state for tests."""
    shell.current_user.setdefault("file_keys", {})[str(file.path)] = (
        file.encrypted_file_key.hex()
    )
    return file


def load_tracked_file(shell, path: Path) -> File:
    """Decrypt a file from disk using the tracked key in shell.current_user."""
    key_hex = shell.current_user["file_keys"][str(path)]
    return File.get_file(path, bytes.fromhex(key_hex))
