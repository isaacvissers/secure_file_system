import os
from pathlib import Path

from dotenv import load_dotenv

SRC_DIR = Path(__file__).resolve().parents[1]
STORAGE_DIR = SRC_DIR / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Allow tests to disable dotenv override behavior for deterministic fixtures.
DOTENV_OVERRIDE = os.getenv("SFS_DOTENV_OVERRIDE", "1") == "1"
load_dotenv(STORAGE_DIR / ".env", override=DOTENV_OVERRIDE)
SALT = os.getenv("SALT", "default_salt")
ADMIN = os.getenv("ADMIN", "admin")
SALT_BYTES = 16
