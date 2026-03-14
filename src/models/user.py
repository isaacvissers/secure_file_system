from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class User:
    username: str
    file_keys: Dict[str, str] = field(default_factory=dict)
    group_keys: List[str] = field(
        default_factory=list
    )  # TODO this needs to be a dict also
    auth_salt: Optional[str] = (
        None  # Random 16 byte salt used for password verification
    )
    auth_verifier: Optional[str] = None  # Argon2 hash of the password + auth_salt


@dataclass
class AdminUser(User):
    user_keys: Dict[str, str] = field(
        default_factory=dict
    )  # Maps encrypted usernames to keys
    group_keys: Dict[str, str] = field(
        default_factory=dict
    )  # Maps encrypted group names to keys
