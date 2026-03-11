import json
import hashlib
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.auth import FILES_DIR


class Permission(Enum):
    USER = "user"
    GROUP = "group"
    ALL = "all"


@dataclass
class File:
    file_name: str
    owner_name: int
    permission: Permission
    encrypted_name: bytes
    body: str
    encrypted_file_key: bytes
    path: Path

    @classmethod
    def create(cls, working_dir: Path, name: str, owner_name: str) -> "File":
        """Create the file on disk as <name>.json and return a File instance."""
        # TODO: make sure we aren't creating files outside of the current user's directory
        # Maybe make sure you are the owner of the parent directory?
        path = working_dir / f"{name}.json"
        if path.exists():
            raise FileExistsError(f"{path} already exists")
        file_key = AESGCM.generate_key(bit_length=256)
        # encrypted_name = hashlib.sha256(str(path).encode("utf-8")).digest()
        encrypted_name = str(path.relative_to(FILES_DIR))  # TODO should be set to encrypted name
        instance = cls(
            file_name=name,  # TODO should be this be encrypted name?
            owner_name=owner_name,
            permission=Permission.USER,  # Default permission
            encrypted_name=encrypted_name,
            body="",
            encrypted_file_key=file_key,
            path=path.relative_to(FILES_DIR),
        )
        instance.save(file_key)
        from backend.file_utils import add_file_to_user

        add_file_to_user(encrypted_name, file_key, owner_name)
        return instance

    @classmethod
    def get_file(cls, path: Path, file_key: bytes | None = None) -> "File":
        """Read the file from disk at <path> and return a File instance."""
        if not path.exists():
            raise FileNotFoundError(f"{path} does not exist")

        if file_key is None:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            payload = path.read_bytes()
            if len(payload) < 13:
                raise ValueError("Encrypted file is too short")
            nonce = payload[:12]
            encrypted_blob = payload[12:]
            decrypted = AESGCM(file_key).decrypt(nonce, encrypted_blob, None)
            data = json.loads(decrypted.decode("utf-8"))

        return cls(
            file_name=data["file_name"],
            owner_name=data["owner_name"],
            permission=Permission(data["permission"]),
            encrypted_name=data["encrypted_name"],
            body=data["body"],
            encrypted_file_key=bytes.fromhex(data["encrypted_file_key"]),
            path=Path(data["path"]),
        )

    def rename_file(self, new_name: str) -> None:
        """Rename the file on disk to <new_name>.json and change File instance to use updated name and path."""
        new_path = self.path.parent / f"{new_name}.json"
        if new_path.exists():
            raise FileExistsError(f"{new_path} already exists")
        # TODO this will have new encrypted name, need to clean up users, and groups that access this file too
        self.path.rename(new_path)
        self.file_name = new_name

    def to_json(self) -> str:
        """Convert the File instance to a JSON string."""
        data = {
            "file_name": self.file_name,
            "owner_name": self.owner_name,
            "permission": self.permission.value,
            "encrypted_name": self.encrypted_name,
            "body": self.body,
            "encrypted_file_key": self.encrypted_file_key.hex(),
            "path": str(self.path),
        }
        return json.dumps(data, indent=4)

    def save(self, file_key: bytes) -> None:
        """Save the File instance encrypted as nonce + ciphertext at its path."""
        data = self.to_json().encode("utf-8")
        nonce = os.urandom(12)
        encrypted_blob = AESGCM(file_key).encrypt(nonce, data, None)
        self.path.write_bytes(nonce + encrypted_blob)
