from dataclasses import dataclass
from typing import List


@dataclass
class User:
    user_id: int
    username: str
    salt: bytes
    password_hash: bytes
    is_admin: bool
    public_key: bytes
    encrypted_private_key: bytes
    private_key_nonce: bytes