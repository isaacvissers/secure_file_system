import os
from pathlib import Path

from dotenv import load_dotenv

SRC_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SRC_DIR.parent
STORAGE_DIR = SRC_DIR / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

load_dotenv(PROJECT_ROOT / ".env")
SALT = os.getenv("SALT", "default_salt")
ADMIN = os.getenv("ADMIN", "admin")
SALT_BYTES = 16
