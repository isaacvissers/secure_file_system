"""
clear_storage.py  –  Delete all contents of the storage directory.

Removes every file and subdirectory inside storage/ recursively while
keeping the top-level storage/ folder and its three root subdirectories
(files, .groups, .users) in place.

Usage:
    python scripts/clear_storage.py
    python scripts/clear_storage.py --yes   # skip confirmation prompt
"""

import argparse
import shutil
from pathlib import Path

STORAGE_DIR = Path(__file__).resolve().parents[1] / "storage"

# Subdirectories to clear (but preserve the directories themselves).
STORAGE_SUBDIRS = ["files", ".groups", ".users"]


def clear_storage(yes: bool = False) -> None:
    if not STORAGE_DIR.exists():
        print(f"Storage directory not found: {STORAGE_DIR}")
        return

    total = sum(
        1
        for subdir in STORAGE_SUBDIRS
        for _ in (STORAGE_DIR / subdir).rglob("*")
        if (STORAGE_DIR / subdir).exists()
    )

    if total == 0:
        print("Storage is already empty.")
        return

    print(f"This will permanently delete {total} item(s) under {STORAGE_DIR}")

    if not yes:
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Aborted.")
            return

    for name in STORAGE_SUBDIRS:
        subdir = STORAGE_DIR / name
        if not subdir.exists():
            continue
        for child in subdir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    print("Storage cleared.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Clear the secure file system storage."
    )
    parser.add_argument(
        "--yes", action="store_true", help="Skip the confirmation prompt."
    )
    args = parser.parse_args()
    clear_storage(yes=args.yes)
