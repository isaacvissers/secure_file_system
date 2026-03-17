import hashlib
from pathlib import Path

import main as main_module
from main import SecureFS
from models.directory import Directory
from models.user import User


def make_user(
    base_path: Path,
    username: str = "alice",
    password: str = "pw",
    *,
    path: Path | None = None,
) -> User:
    salt = "testsalt"
    verifier = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    user_path = path or (base_path / f"{username}.user.json")
    user = User(
        username=username,
        auth_salt=salt,
        auth_verifier=verifier,
        path=user_path,
    )
    user.save()
    return user


def make_logged_in_shell(
    tmp_path: Path, monkeypatch, username: str = "alice"
) -> SecureFS:
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    user = make_user(tmp_path, username=username)
    user_home = Directory.create(tmp_path, username, user)

    shell = SecureFS()
    shell.current_user = user
    shell.current_user_key = None
    shell.current_working_directory = user_home.path
    shell._update_prompt()
    return shell
