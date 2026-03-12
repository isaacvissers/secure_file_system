from dataclasses import dataclass
from pathlib import Path

from models.file import File


@dataclass
class Directory:
    metadata: File
    path: Path

    @classmethod
    def create(cls, working_dir: Path, name: str, owner_name: str) -> "Directory":
        """Create the directory on disk and return a Directory instance."""
        metadata = File.create(working_dir, name, owner_name)
        path = working_dir / name
        if path.exists():
            raise FileExistsError(f"{path} already exists")
        path.mkdir(parents=True, exist_ok=False)
        return cls(path=path, metadata=metadata)
