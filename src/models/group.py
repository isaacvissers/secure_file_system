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
    ) -> "Group":
        """Create the group on disk as <name> and return a Group instance."""
        master_key = os.urandom(32).hex()
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
        instance.save()

        return instance, master_key

    @classmethod
    def get_group(cls, path: Path, file_key: bytes | None = None) -> "Group":
        """Load and decrypt a group record by group name."""
        if file_key is None:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            payload = path.read_bytes()
            # if len(payload) < 13:
            #     raise ValueError("Encrypted file is too short")
            # nonce = payload[:12]
            # encrypted_blob = payload[12:]
            # decrypted = AESGCM(file_key).decrypt(nonce, encrypted_blob, None)
            # data = json.loads(decrypted.decode("utf-8"))
            # TODO: REMOVE!!!
            data = json.loads(payload.decode("utf-8"))
        return cls(**data)

    def to_json(self) -> str:
        data = asdict(self)
        if "encrypted_file_key" in data:
            del data["encrypted_file_key"]

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

        output_path = Path(self.path)
        json_data = self.to_json()

        output_path.write_text(json_data, encoding="utf-8")
