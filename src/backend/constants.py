import os

from dotenv import load_dotenv

from backend.storage_paths import get_storage_dir

STORAGE_DIR = get_storage_dir()

# Allow tests to disable dotenv override behavior for deterministic fixtures.
DOTENV_OVERRIDE = os.getenv("SFS_DOTENV_OVERRIDE", "1") == "1"
load_dotenv(STORAGE_DIR / ".env", override=DOTENV_OVERRIDE)
SALT = os.getenv("SALT", "default_salt")
ADMIN = os.getenv("ADMIN", "admin")
SALT_BYTES = 16
