from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1]
STORAGE_DIR = SRC_DIR / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

SALT = "psalt"
SALT_BYTES = 16
ADMIN = "admin"
