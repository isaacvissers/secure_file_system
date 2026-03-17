import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models.user import User


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
        user: User,
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
            owner_name=user.username,
            permission=permission,
            encrypted_name=encrypted_name,
            body=body,
            encrypted_file_key=file_key,
            path=real_path,
        )
        instance.save()
        from backend.file_utils import add_file_to_user

        add_file_to_user(str(real_path), user, file_key)
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
            encrypted_blob = payload[12:-64]
            stored_hash = payload[-64:].decode("utf-8")
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

    def rename_file(self, user: User, new_name: str) -> None:
        """Rename the file on disk to <new_name> and change File instance to use updated name and path."""
        # TODO we need to handle the case with directories afterwards
        File.create(self.path.parent, new_name, user, self.body, self.permission)

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
        # self.path.write_bytes(nonce + encrypted_blob)
        # Add some integrity check by saving a hash of the encrypted content
        integrity_hash = hashlib.sha256(nonce + encrypted_blob).hexdigest()
        self.path.write_bytes((nonce + encrypted_blob) + integrity_hash.encode("utf-8"))

        # Keep user file_info in sync whenever file bytes are rewritten.
        from backend.file_utils import \
            sync_file_info_for_user  # must be here to avoid circular imports

        sync_file_info_for_user(self.owner_name, self.path, self.encrypted_file_key)

    def check_integrity(self) -> bool:
        """Check the integrity of the file by comparing the stored hash with a hash of the current content."""
        content = self.path.read_bytes()
        if len(content) < 64:  # nonce (12) + encrypted_blob (at least 1) + hash (32)
            return False
        nonce = content[:12]
        encrypted_blob = content[12:-64]
        stored_hash = content[-64:].decode("utf-8")
        computed_hash = hashlib.sha256(nonce + encrypted_blob).hexdigest()
        return stored_hash == computed_hash

        # return True  # Placeholder for actual integrity check logic
