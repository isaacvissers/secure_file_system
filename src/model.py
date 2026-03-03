from dataclasses import dataclass
from typing import List


@dataclass
class User:
    user_id: int
    username: str
    salt: bytes
    pasword_hash: bytes
    is_admin: bool
    group_ids: List[int]
