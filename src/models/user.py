from dataclasses import dataclass, field
from typing import Dict, List, TypeAlias

FileInfo: TypeAlias = str  # decrypted file name


@dataclass
class User:
    username: str
    file_keys: Dict[str, str] = field(default_factory=dict)
    file_info: Dict[str, FileInfo] = field(default_factory=dict)
    group_keys: List[str] = field(
        default_factory=list
    )  # TODO this needs to be a dict also


@dataclass
class AdminUser(User):
    user_keys: Dict[str, str] = field(
        default_factory=dict
    )  # Maps encrypted usernames to keys
    group_keys: Dict[str, str] = field(
        default_factory=dict
    )  # Maps encrypted group names to keys
