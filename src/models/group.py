from dataclasses import dataclass
from typing import List

@dataclass
class Group:
    group_id: int
    group_name: str
    members: List[str]
    file_access: List[str]