import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, TypeAlias

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.constants import ADMIN, SALT
from backend.storage_paths import get_storage_dir
from models.group import Group

USERS_DIR = get_storage_dir() / ".users"
USERS_DIR.mkdir(parents=True, exist_ok=True)

FileInfo: TypeAlias = str  # decrypted file name


def derive_user_file_key(username: str, password: str) -> bytes:
    """Deterministically derive the AES key used to encrypt a user's record."""
    salt = os.getenv("SALT", SALT)
    raw = f"{username}_{password}_{salt}"
    return hashlib.sha256(raw.encode("utf-8")).digest()


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
        master_key = derive_user_file_key(name, password)
        encrypted_name = hashlib.sha256(name.encode("utf-8")).hexdigest()
        real_path = USERS_DIR / encrypted_name

        salt = os.urandom(16).hex()
        verifier = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()

        instance = cls(
            username=name, auth_salt=salt, auth_verifier=verifier, path=str(real_path)
        )
        instance._encryption_key = master_key
        instance.save(master_key)
        return instance, master_key

    @classmethod
    def get_user(
        cls, path: Path, file_key: bytes | None = None
    ) -> Tuple[Optional["User"], Optional[bytes]]:
        """Load and decrypt a user record."""
        if file_key is None:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None, None
            data["path"] = str(path)
            user = cls(**data)
            return user, None

        try:
            payload = path.read_bytes()
            if len(payload) < 13:
                return None, None

            nonce = payload[:12]
            ciphertext = payload[12:]

            aesgcm = AESGCM(file_key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            data = json.loads(decrypted.decode("utf-8"))
            data["path"] = str(path)
            user = cls(**data)
            user._encryption_key = file_key
            return user, file_key
        except Exception:
            return None, None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4, default=str)

    def save(self, file_key: bytes | str) -> None:
        """Encrypt and save the user record."""
        if not self.path:
            raise ValueError("User path not set")

        if isinstance(file_key, str):
            try:
                file_key = bytes.fromhex(file_key)
            except ValueError:
                file_key = hashlib.sha256(file_key.encode()).digest()

        if not file_key:
            raise ValueError("File key is required to encrypt user data.")

        json_data = self.to_json().encode("utf-8")
        nonce = os.urandom(12)
        aesgcm = AESGCM(file_key)
        ciphertext = aesgcm.encrypt(nonce, json_data, None)
        Path(self.path).write_bytes(nonce + ciphertext)

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
