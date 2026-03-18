import json
from pathlib import Path

import backend.auth as auth
from models.user import AdminUser, User


def test_create_user_key_and_admin_key():
    assert auth.create_user_key("alice", "pw") == "alice_pw_psalt"
    assert auth.get_admin_key() == "admin_admin_psalt"


def test_requires_login_blocks_when_logged_out(capsys):
    class Shell:
        current_user = None

    @auth.requires_login
    def action(self, arg):
        print(f"ran {arg}")

    action(Shell(), "x")
    assert "Must be logged in." in capsys.readouterr().out


def test_requires_logged_out_blocks_when_logged_in(capsys):
    class Shell:
        current_user = object()

    @auth.requires_logged_out
    def action(self, arg):
        print(f"ran {arg}")

    action(Shell(), "x")
    assert "Already logged in." in capsys.readouterr().out


def test_requires_admin_blocks_non_admin(capsys):
    class Shell:
        current_user = User(username="alice")

    @auth.requires_admin
    def action(self, arg):
        print(f"ran {arg}")

    action(Shell(), "x")
    assert "Must be logged in as Admin" in capsys.readouterr().out


def test_create_user_directory_calls_directory_create(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "FILES_DIR", tmp_path)
    calls = {}

    def fake_create(base: Path, name: str, user: User):
        calls["base"] = base
        calls["name"] = name
        calls["user"] = user
        return "created-dir"

    monkeypatch.setattr(auth.Directory, "create", fake_create)

    user = User(username="mike")
    assert auth.create_user_directory(user) == "created-dir"
    assert calls == {"base": tmp_path, "name": "mike", "user": user}


def test_add_user_to_admin_updates_admin_mapping(tmp_path):
    admin_path = tmp_path / "admin.json"
    admin = AdminUser(
        username="admin",
        auth_salt="salt",
        auth_verifier="verifier",
        path=admin_path,
    )
    admin_file_key = b"\xaa" * 32
    admin.save(admin_file_key)

    target_path = tmp_path / "target-user-file"
    target = User(username="neo", path=target_path)

    auth.add_user_to_admin(admin, target, "masterkey123", admin_file_key)

    loaded_admin, _ = AdminUser.get_user(admin_path, admin_file_key)
    assert loaded_admin is not None
    assert loaded_admin.user_keys["neo"]["id"] == target_path.name
    assert loaded_admin.user_keys["neo"]["key"] == "masterkey123"


def test_user_file_path_uses_users_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    assert auth._user_file_path("bob") == tmp_path / "bob.json"
