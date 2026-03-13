import hashlib
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
        encrypted_name = hashlib.sha256(name.encode("utf-8")).hexdigest()

        real_path = working_dir / encrypted_name
        if real_path.exists():
            raise FileExistsError(f"{real_path} already exists")
        real_path.mkdir(parents=True, exist_ok=False)
        return cls(
            path=real_path,
            metadata=File.create(working_dir, name, owner_name, is_metadata=True),
        )

        metadata = File.create(working_dir, "." + name, owner_name)

        if path.exists():
            raise FileExistsError(f"{path} already exists")
        path.mkdir(parents=True, exist_ok=False)
        return cls(path=path, metadata=metadata)
