import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List


class Permission(Enum):
    USER = "user"
    GROUP = "group"
    ALL = "all"


@dataclass
class File:
    file_name: str
    owner_name: int
    permission: Permission
    encrypted_name: bytes
    encrypted_body: bytes
    encrypted_file_key: bytes
    path: Path

    @classmethod
    def create(cls, working_dir: Path, name: str) -> "File":
        """Create the file on disk as <name>.json and return a File instance."""
        # TODO: make sure we aren't creating files outside of the current user's directory
        path = working_dir / f"{name}.json"
        if path.exists():
            raise FileExistsError(f"{path} already exists")
        instance = cls(
            file_name=name,
            owner_name=0,  # Placeholder, should be set to current user's ID
            permission=Permission.USER,  # Default permission
            encrypted_name=name.encode(),  # Placeholder, should be set to encrypted name
            encrypted_body=b"",  # Placeholder, should be set to encrypted body
            encrypted_file_key=b"",  # Placeholder, should be set to encrypted file key
            path=path,
        )
        data = cls.to_json(instance)
        path.write_text(data, encoding="utf-8")
        return instance

    def to_json(self) -> str:
        """Convert the File instance to a JSON string."""
        data = {
            "file_name": self.file_name,
            "owner_name": self.owner_name,
            "permission": self.permission.value,
            "encrypted_name": self.encrypted_name.hex(),
            "encrypted_body": self.encrypted_body.hex(),
            "encrypted_file_key": self.encrypted_file_key.hex(),
            "path": str(self.path),
        }
        return json.dumps(data, indent=4)


@dataclass
class Directory:
    metadata: File
    path: Path

    @classmethod
    def create(cls, working_dir: Path, name: str) -> "Directory":
        """Create the directory on disk and return a Directory instance."""
        metadata = File.create(working_dir, name)
        path = working_dir / name
        if path.exists():
            raise FileExistsError(f"{path} already exists")
        path.mkdir(parents=True, exist_ok=False)
        return cls(path=path, metadata=metadata)
