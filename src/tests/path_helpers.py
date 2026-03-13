import hashlib
from pathlib import Path


def encrypted_name(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def encrypted_path(parent: Path, name: str, *, metadata: bool = False) -> Path:
    hashed = encrypted_name(name)
    if metadata:
        hashed = f".{hashed}"
    return parent / hashed
