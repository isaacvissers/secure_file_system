from dataclasses import dataclass
from typing import Dict, List


@dataclass
class User:
    username: str
    file_keys: List[str]
    group_keys: List[str]

@dataclass
class AdminUser(User):
    user_keys: Dict[str, str]  # Maps encrypted usernames to keys
    group_keys: Dict[str, str]  # Maps encrypted group names to keys
