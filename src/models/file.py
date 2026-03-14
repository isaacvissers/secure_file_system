import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Permission(Enum):
    USER = "user"
    GROUP = "group"
    ALL = "all"


@dataclass
class File:
    file_name: str
    owner_name: str
    permission: Permission
    encrypted_name: str
    body: str
    encrypted_file_key: bytes
    path: Path

    @classmethod
    def create(
        cls,
        working_dir: Path,
        name: str,
        owner_name: str,
        body: str = "",
        permission: Permission = Permission.USER,
        is_metadata: bool = False,
    ) -> "File":
        """Create the file on disk as <name> and return a File instance."""
        # TODO: make sure we aren't creating files outside of the current user's directory
        # Maybe make sure you are the owner of the parent directory?
        encrypted_name = hashlib.sha256(name.encode("utf-8")).hexdigest()
        if is_metadata:
            encrypted_name = f".{encrypted_name}"
        file_key = AESGCM.generate_key(bit_length=256)
        real_path = working_dir / encrypted_name
        if real_path.exists():
            raise FileExistsError(f"{real_path} already exists")
        instance = cls(
            file_name=name,
            owner_name=owner_name,
            permission=permission,
            encrypted_name=encrypted_name,
            body=body,
            encrypted_file_key=file_key,
            path=real_path,
        )
        instance.save()
        from backend.file_utils import add_file_to_user

        add_file_to_user(str(real_path), file_key, owner_name)
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
        """Rename the file on disk to <new_name> and change File instance to use updated name and path."""
        # TODO we need to handle the case with directories afterwards
        File.create(
            self.path.parent, new_name, self.owner_name, self.body, self.permission
        )

        # delete the old file
        # TODO need to remove the file completely, which will require accessing user and groups
        self.path.unlink()

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

    def save(self) -> None:
        """Save the File instance encrypted as nonce + ciphertext at its path."""
        data = self.to_json().encode("utf-8")
        nonce = os.urandom(12)
        encrypted_blob = AESGCM(self.encrypted_file_key).encrypt(nonce, data, None)
        self.path.write_bytes(nonce + encrypted_blob)  # TODO add integrity check here.
