import json

from backend import auth


def test_create_user_key_and_admin_key():
    k = auth.create_user_key("alice", "pw")
    assert "alice" in k and "pw" in k
    assert auth.get_admin_key() == auth.create_user_key("admin", "admin")


def test_save_and_load_user_without_admin_index(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    user = {"username": "bob", "file_keys": [], "group_keys": []}
    key = auth.create_user_key("bob", "pw")
    auth.save_user(key, user)

    # load_user should find by scanning when no admin exists
    loaded = auth.load_user("bob")
    assert loaded is not None and loaded["username"] == "bob"


def test_create_user_writes_file_and_updates_admin_index(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    # create an admin record first so create_user will add mapping
    admin_key = auth.get_admin_key()
    with open(tmp_path / f"{admin_key}.json", "w", encoding="utf-8") as f:
        json.dump({"username": "admin", "user_keys": {}}, f)

    # avoid creating real directories in tests
    monkeypatch.setattr(auth, "create_user_directory", lambda _k: None)

    created = auth.create_user("carol", "secret", is_admin=False)
    assert created is not None

    user_key = auth.create_user_key("carol", "secret")
    assert (tmp_path / f"{user_key}.json").exists()

    # admin file should have been updated with mapping
    with open(tmp_path / f"{admin_key}.json", "r", encoding="utf-8") as f:
        admin_data = json.load(f)
    assert admin_data.get("user_keys", {}).get("carol") == user_key


def test_user_exists_and_get_admin_record(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    # write a simple user file
    with open(tmp_path / "some.json", "w", encoding="utf-8") as f:
        json.dump({"username": "dana"}, f)

    assert auth.user_exists("dana") is True
    assert auth.user_exists("nope") is False

    # test get_admin_record returns None when missing and AdminUser when present
    assert auth.get_admin_record() is None
    admin_key = auth.get_admin_key()
    with open(tmp_path / f"{admin_key}.json", "w", encoding="utf-8") as f:
        json.dump({"username": "admin", "user_keys": {}}, f)
    admin = auth.get_admin_record()
    assert admin is not None
    assert getattr(admin, "user_keys", {}) == {}


def test_resolve_user_with_admin_index(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    # prepare user file and admin mapping
    key = auth.create_user_key("erin", "pw")
    with open(tmp_path / f"{key}.json", "w", encoding="utf-8") as f:
        json.dump({"username": "erin", "file_keys": [], "group_keys": []}, f)

    admin_key = auth.get_admin_key()
    with open(tmp_path / f"{admin_key}.json", "w", encoding="utf-8") as f:
        json.dump({"username": "admin", "user_keys": {"erin": key}}, f)

    admin = auth.get_admin_record()
    assert admin is not None

    user_key, user = auth._resolve_user(admin, "erin")
    assert user_key == key
    assert user is not None and user.get("username") == "erin"
