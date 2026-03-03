from dataclasses import dataclass
from typing import List

@dataclass
class Group:
    group_id: int
    group_name: str
    members: List[str] # will update to [user.user_id, key]
    file_access: List[str] # will update to [file.file_id, key]