import json

from backend import auth, files_utils
from scripts import create_admin


def test_save_user_writes_expected_json_file(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    user_dict = {"username": "alice", "file_keys": [], "group_keys": []}
    key = auth.create_user_key("alice", "pw")

    auth.save_user(key, user_dict)

    user_file = tmp_path / f"{key}.json"
    assert user_file.exists()

    with open(user_file, "r") as file:
        saved_data = json.load(file)

    assert saved_data == user_dict


def test_user_exists_returns_true_when_username_present(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    # filenames must match the queried username (current auth implementation
    # checks file stems), so create files named after usernames.
    with open(tmp_path / "alice.json", "w") as file:
        json.dump({"username": "alice"}, file)

    with open(tmp_path / "bob.json", "w") as file:
        json.dump({"username": "bob"}, file)

    assert auth.user_exists("alice") is True


def test_user_exists_returns_false_when_username_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    with open(tmp_path / "alice.json", "w") as file:
        json.dump({"username": "alice"}, file)

    assert auth.user_exists("charlie") is False


def test_load_user_returns_user_by_username_with_admin_index(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    # create a user file and an admin index mapping the username to that key
    user = {"username": "dana", "file_keys": [], "group_keys": []}
    key = auth.create_user_key("dana", "pw")
    with open(tmp_path / f"{key}.json", "w") as file:
        json.dump(user, file)

    # create admin index mapping
    admin_key = auth.get_admin_key()
    with open(tmp_path / f"{admin_key}.json", "w") as file:
        json.dump({"username": "admin", "user_keys": {"dana": key}}, file)

    loaded = auth.load_user("dana")

    assert loaded is not None and loaded["username"] == "dana"


def test_create_user_saves_user_with_expected_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    created = auth.create_user("eve", "secret", is_admin=True)

    assert created is not None
    assert created["username"] == "eve"
    assert "user_keys" in created

    user_file = tmp_path / f"{auth.create_user_key('eve','secret')}.json"
    assert user_file.exists()


def test_create_user_returns_none_when_username_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    # create a file whose stem equals the username
    with open(tmp_path / "frank.json", "w") as file:
        json.dump({"username": "frank"}, file)

    created = auth.create_user("frank", "another-secret")

    assert created is None


def test_ensure_admin_user_resets_password_when_requested(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(create_admin, "USERS_DIR", tmp_path)
    # ensure_admin_user should be present and able to reset
    admin_key = auth.get_admin_key()
    with open(tmp_path / f"{admin_key}.json", "w") as file:
        json.dump({"username": "admin", "user_keys": {"admin": admin_key}}, file)

    user_data, status = create_admin.ensure_admin_user(
        "admin", "new-password", reset_password=True
    )

    assert status in ("created", "updated")


def test_create_user_creates_home_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(files_utils, "FILES_DIR", tmp_path)
    user_dict = auth.create_user("tester", "password", is_admin=False)
    key = auth.create_user_key("tester", "password")
    user_dir = tmp_path / f"user_{key}"
    assert user_dir.exists() and user_dir.is_dir()


def test_create_admin_doesnt_create_home_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(files_utils, "FILES_DIR", tmp_path)
    user_dict = auth.create_user("tester", "password", is_admin=True)
    key = auth.create_user_key("tester", "password")
    user_dir = tmp_path / f"user_{key}"
    assert not user_dir.exists() and not user_dir.is_dir()
