from dataclasses import dataclass
from enum import Enum
from typing import List


class Permission(Enum):
    USER = "user"
    GROUP = "group"
    ALL = "all"

class FileType(Enum):
    FILE = "file"
    DIR = "dir"

@dataclass
class File:
    file_id: int
    owner_id: int
    group_ids: List[int]
    permission: Permission
    type: FileType
    encrypted_name: bytes
    encrypted_body: bytes
    encrypted_file_key: bytes
    parent_id: int
    children: List[int]
    integrity_tag: bytes
