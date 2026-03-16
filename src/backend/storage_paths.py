import sys
from pathlib import Path


def get_runtime_base_dir() -> Path:
    """Return the base directory to store runtime data.

    - When running from a PyInstaller binary, use the executable directory.
    - When running from source, use the project src directory.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    return Path(__file__).resolve().parents[1]


def get_storage_dir() -> Path:
    storage_dir = get_runtime_base_dir() / "storage"
    storage_dir.mkdir(parents=True, exist_ok=True)
    return storage_dir
