from functools import wraps
from getpass import getpass
from typing import Optional, Tuple


def prompt_required_text(label: str) -> Optional[str]:
    value = input(f"{label}: ").strip()
    if not value:
        print(f"Error: {label.capitalize()} cannot be empty.")
        return None
    return value


def prompt_password() -> Optional[str]:
    password = getpass("password: ")
    if not password:
        print("Error: Password cannot be empty.")
        return None
    return password


def prompt_yes_no(label: str) -> bool:
    choice = input(f"{label} (y/n): ").strip().lower()
    while choice not in {"y", "n"}:
        choice = input(f"{label} (y/n): ").strip().lower()
    return choice == "y"


def prompt_credentials() -> Optional[Tuple[str, str]]:
    username = prompt_required_text("username")
    if username is None:
        return None

    password = prompt_password()
    if password is None:
        return None

    return username, password
