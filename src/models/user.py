from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class User:
    username: str
    file_keys: Dict[str, str] = field(default_factory=dict)
    group_keys: Dict[str, Dict[str, str]] = field(
        default_factory=dict
    )  # Maps group names to dicts with 'file_path' and 'encryption_key'
    auth_salt: Optional[str] = (
        None  # Random 16 byte salt used for password verification
    )
    auth_verifier: Optional[str] = None  # Argon2 hash of the password + auth_salt


@dataclass
class AdminUser(User):
    user_keys: Dict[str, Dict[str, str]] = field(
        default_factory=dict
    )  # Maps usernames to encrypted user metadata
    group_keys: Dict[str, Dict[str, str]] = field(
        default_factory=dict
    )  # Maps group names to encrypted group metadata
