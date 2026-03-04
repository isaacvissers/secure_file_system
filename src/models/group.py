from dataclasses import dataclass
from typing import Dict


@dataclass
class Group:
    group_name: str
    members: Dict[str, str]  # List of encrypted usernames to their actual usernames
    file_access: Dict[str, str]
