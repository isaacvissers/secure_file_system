import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from isort import file


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
    
    @classmethod
    def get_file(cls, path: Path) -> "File":
        """Read the file from disk at <path> and return a File instance."""
        if not path.exists():
            raise FileNotFoundError(f"{path} does not exist")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return cls(
                file_name=data["file_name"],
                owner_name=data["owner_name"],
                permission=Permission(data["permission"]),
                encrypted_name=data["encrypted_name"],
                encrypted_body=data["encrypted_body"],
                encrypted_file_key=data["encrypted_file_key"],
                path=Path(data["path"]),
            )
    
    def rename_file(self, new_name: str) -> None:
        """Rename the file on disk to <new_name>.json and change File instance to use updated name and path."""
        new_path = self.path.parent / f"{new_name}.json"
        if new_path.exists():
            raise FileExistsError(f"{new_path} already exists")
        self.path.rename(new_path)
        self.file_name = new_name

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
