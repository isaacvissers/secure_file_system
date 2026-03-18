import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from pathlib import Path as _Path
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SRC_DIR = _Path(__file__).resolve().parents[1]
GROUPS_DIR = SRC_DIR / "storage/.groups"
GROUPS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class Group:
    group_name: str
    encrypted_name: str
    members: Dict[str, str]  # {username: path}
    file_access: Dict[
        str, Dict[str, str]
    ]  # {filename: {id: 16-byte file name, key: 32-byte file key}}
    path: Path
    encrypted_file_key: Optional[bytes] = None

    @classmethod
    def create(
        cls,
        name: str,
    ) -> tuple["Group", bytes]:
        """Create the group on disk as <name> and return a Group instance."""
        master_key = os.urandom(32)
        encrypted_name = hashlib.sha256(name.encode("utf-8")).hexdigest()
        file_key = AESGCM.generate_key(bit_length=256)
        real_path = GROUPS_DIR / encrypted_name
        instance = cls(
            group_name=name,
            encrypted_name=encrypted_name,
            members={},
            file_access={},
            encrypted_file_key=file_key,
            path=real_path,
        )
        instance.save(master_key)

        return instance, master_key

    @classmethod
    def get_group(cls, path: Path, file_key: bytes | None = None) -> "Group":
        """Load and decrypt a group record by group name."""
        payload = path.read_bytes()
        if len(payload) < 13:
            raise ValueError("Encrypted file is too short")

        nonce = payload[:12]
        encrypted_blob = payload[12:]

        decrypted = AESGCM(file_key).decrypt(nonce, encrypted_blob, None)
        data = json.loads(decrypted.decode("utf-8"))

        if "path" in data:
            data["path"] = Path(data["path"])

        if data.get("encrypted_file_key"):
            data["encrypted_file_key"] = bytes.fromhex(data["encrypted_file_key"])

        return cls(**data)

    def to_json(self) -> str:
        data = asdict(self)

        def serializer(obj):
            if isinstance(obj, Path):
                return str(obj)
            if isinstance(obj, bytes):
                return obj.hex()
            raise TypeError(f"Type {type(obj)} not serializable")

        return json.dumps(data, indent=4, default=serializer)

    def save(self, file_key: bytes | None = None) -> None:
        if not self.path:
            raise ValueError("Group path not set")

        if file_key is None:
            raise ValueError("File key required for secure group save")

        plaintext = self.to_json().encode("utf-8")
        nonce = os.urandom(12)
        aesgcm = AESGCM(file_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        self.path.write_bytes(nonce + ciphertext)
