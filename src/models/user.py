import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, TypeAlias

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models.group import Group

SRC_DIR = Path(__file__).resolve().parents[1]
USERS_DIR = SRC_DIR / "storage/.users"
USERS_DIR.mkdir(parents=True, exist_ok=True)
ADMIN = "admin"

FileInfo: TypeAlias = str  # decrypted file name


@dataclass
class User:
    username: str
    auth_salt: Optional[str] = None
    auth_verifier: Optional[str] = None
    path: Optional[str] = None
    file_keys: Dict[str, str] = field(default_factory=dict)
    file_info: Dict[str, FileInfo] = field(default_factory=dict)
    user_keys: Dict[str, str] = field(
        default_factory=dict
    )  # {username: {id: 16-byte file name, key: 32-byte file key}}
    group_keys: Dict[str, str] = field(
        default_factory=dict
    )  # {groupname: {id: 16-byte group name, key: 32-byte group key}}

    @classmethod
    def create(cls, name: str, password: str):
        master_key = os.urandom(32).hex()
        encrypted_name = hashlib.sha256(name.encode("utf-8")).hexdigest()
        real_path = USERS_DIR / encrypted_name

        salt = os.urandom(16).hex()
        verifier = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()

        instance = cls(
            username=name, auth_salt=salt, auth_verifier=verifier, path=real_path
        )
        instance.save()
        return instance, master_key

    @classmethod
    def get_user(cls, path: Path, file_key: bytes | None = None) -> Optional["User"]:
        if file_key is None:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                return None
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

        data["path"] = Path(path) if isinstance(path, (str, Path)) else path
        return cls(**data), file_key

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4, default=str)

    def save(self) -> None:
        if not self.path:
            raise ValueError("User path not set")
        Path(self.path).write_text(self.to_json(), encoding="utf-8")

    def verify_password(self, password: str) -> bool:
        """Hash the provided password with the stored salt and compare."""
        attempt = hashlib.sha256(
            (password + self.auth_salt).encode("utf-8")
        ).hexdigest()
        return attempt == self.auth_verifier
    
    def get_encrypted_name(self) -> str:
        """Return the encrypted name of the user for storage purposes."""
        return hashlib.sha256(self.username.encode("utf-8")).hexdigest()

    def get_file_key(self, file_path: Path) -> Optional[str]:
        """Retrieve the file key for a given file path from the user's metadata."""
        key_hex = self.file_keys.get(str(file_path))
        if key_hex is None:
            # Check group keys if user doesn't have direct access
            for group_name, group_info in self.group_keys.items():
                group_key = bytes.fromhex(group_info["key"])
                group_id = group_info["id"]
                group_obj = Group.get_group(Path(group_id), group_key)
                if str(file_path) in group_obj.file_access.keys():
                    key_hex = group_obj.file_access[str(file_path)]["key"]
                    break
        return key_hex if key_hex else None

@dataclass
class AdminUser(User):
    pass

    @classmethod
    def load_from_json(cls, data: dict, path: Path) -> "AdminUser":
        data["path"] = path
        return cls(**data)
