import os

from dotenv import load_dotenv

from backend.storage_paths import get_storage_dir

STORAGE_DIR = get_storage_dir()

load_dotenv(STORAGE_DIR / ".env", override=True)
SALT = os.getenv("SALT", "default_salt")
ADMIN = os.getenv("ADMIN", "admin")
SALT_BYTES = 16
