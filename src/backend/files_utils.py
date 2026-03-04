from pathlib import Path
from typing import Any, Dict

SRC_DIR = Path(__file__).resolve().parents[1]

FILES_DIR = SRC_DIR / "storage/.files"
FILES_DIR.mkdir(parents=True, exist_ok=True)

FilesDict = Dict[str, Any]


def create_user_directory(user_id: int) -> Path:
    user_dir = FILES_DIR / f"user_{user_id}"
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir
