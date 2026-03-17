import json
from pathlib import Path

import backend.auth as auth
from models.user import AdminUser, User


def test_create_user_key_and_admin_key():
    key = auth.create_user_key("alice", "pw")
    assert key == "alice_pw_psalt"
    assert auth.get_admin_key() == "admin_admin_psalt"


def test_save_and_load_user_without_admin_index(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(auth, "_user_file_path", lambda user_key: tmp_path / f"{user_key}.json")

    user = {"username": "bob", "file_keys": {}, "group_keys": {}}
    key = auth.create_user_key("bob", "pw")
    auth.save_user(key, user)

    loaded = auth.load_user("bob")
    assert loaded is not None
    assert loaded["username"] == "bob"


def test_get_admin_record_missing_and_present(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(auth, "_user_file_path", lambda user_key: tmp_path / f"{user_key}.json")

    assert auth.get_admin_record() is None

    admin_key = auth.get_admin_key()
    admin_path = tmp_path / f"{admin_key}.json"
    with open(admin_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "username": "admin",
                "path": str(admin_path),
                "user_keys": {"u1": "u1_pw_psalt"},
                "group_keys": {},
            },
            f,
        )

    admin = auth.get_admin_record()
    assert isinstance(admin, AdminUser)
    assert admin.user_keys["u1"] == "u1_pw_psalt"


def test_load_user_uses_admin_index_when_available(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(auth, "_user_file_path", lambda user_key: tmp_path / f"{user_key}.json")

    user_key = auth.create_user_key("erin", "pw")
    with open(tmp_path / f"{user_key}.json", "w", encoding="utf-8") as f:
        json.dump({"username": "erin", "file_keys": {}, "group_keys": {}}, f)

    admin_key = auth.get_admin_key()
    admin_path = tmp_path / f"{admin_key}.json"
    with open(admin_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "username": "admin",
                "path": str(admin_path),
                "user_keys": {"erin": user_key},
                "group_keys": {},
            },
            f,
        )

    loaded = auth.load_user("erin")
    assert loaded is not None
    assert loaded["username"] == "erin"


def test_resolve_user_with_admin_index(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(auth, "_user_file_path", lambda user_key: tmp_path / f"{user_key}.json")

    user_key = auth.create_user_key("zara", "pw")
    with open(tmp_path / f"{user_key}.json", "w", encoding="utf-8") as f:
        json.dump({"username": "zara", "file_keys": {}, "group_keys": {}}, f)

    admin_key = auth.get_admin_key()
    admin_path = tmp_path / f"{admin_key}.json"
    with open(admin_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "username": "admin",
                "path": str(admin_path),
                "user_keys": {"zara": user_key},
                "group_keys": {},
            },
            f,
        )

    admin = auth.get_admin_record()
    resolved_key, user_dict = auth._resolve_user(admin, "zara")

    assert resolved_key == user_key
    assert user_dict is not None
    assert user_dict["username"] == "zara"


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
    result = auth.create_user_directory(user)

    assert result == "created-dir"
    assert calls["base"] == tmp_path
    assert calls["name"] == "mike"
    assert calls["user"].username == "mike"


def test_add_user_to_admin_updates_admin_mapping(tmp_path):
    admin_path = tmp_path / "admin.json"
    admin = AdminUser(username="admin", path=str(admin_path), user_keys={}, group_keys={})
    admin.save()

    target_path = tmp_path / "target-user-file"
    target = User(username="neo", path=str(target_path))

    auth.add_user_to_admin(admin, target, "masterkey123")

    with open(admin_path, "r", encoding="utf-8") as f:
        saved = json.load(f)

    assert saved["user_keys"]["neo"]["id"] == target_path.name
    assert saved["user_keys"]["neo"]["key"] == "masterkey123"
