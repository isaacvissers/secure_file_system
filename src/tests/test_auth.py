import hashlib
import json
import os

import backend.auth as auth
from scripts import create_admin


def test_create_user_key_and_admin_key():
    k = auth.create_admin_login_token("alice", "pw")
    assert "alice" in k and "pw" in k
    assert auth.get_admin_key() == auth.create_admin_login_token("admin", "admin")


def test_save_and_load_user_without_admin_index(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    auth.save_admin_record(
        {
            "username": "admin",
            "file_keys": {},
            "group_keys": {},
            "user_keys": {},
        }
    )

    user = {"username": "bob", "file_keys": [], "group_keys": {}}
    key = os.urandom(16).hex()
    record_key = os.urandom(32)
    auth.save_user(key, user, record_key=record_key)
    auth.add_user_key_to_admin("bob", key, record_key.hex())

    loaded = auth.load_user("bob")
    assert loaded is not None and loaded["username"] == "bob"


def test_create_user_writes_file_and_updates_admin_index(tmp_path, monkeypatch):
    import backend.group_utils as group_utils

    users_dir = tmp_path / ".users"
    groups_dir = tmp_path / ".groups"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    groups_dir.mkdir()
    files_dir.mkdir()

    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)
    monkeypatch.setattr(
        auth, "_user_file_path", lambda user_key: users_dir / f"{user_key}.json"
    )

    # create an admin record first so create_user will add mapping
    admin_key = auth.get_admin_key()
    auth.save_admin_record(
        {
            "username": "admin",
            "file_keys": {},
            "group_keys": {},
            "user_keys": {},
        }
    )

    # Create the "all" group
    group_utils.create_group("all")

    # avoid creating real directories in tests
    monkeypatch.setattr(auth, "create_user_directory", lambda _k: None)

    created = auth.create_user("carol", "secret", is_admin=False)
    assert created is not None

    # admin index should have been updated with mapping
    admin_data = auth.get_admin_record()
    assert admin_data is not None

    entry = admin_data.user_keys.get("carol")
    if isinstance(entry, dict):
        user_key = entry.get("id")
        record_key_hex = entry.get("record_key")
        assert isinstance(record_key_hex, str) and len(record_key_hex) == 64
    else:
        user_key = entry

    assert isinstance(user_key, str) and len(user_key) > 0
    assert user_key != auth.create_admin_login_token("carol", "secret")
    assert (users_dir / f"{user_key}.json").exists()


def test_user_exists_and_get_admin_record(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    auth.save_admin_record(
        {
            "username": "admin",
            "file_keys": {},
            "group_keys": {},
            "user_keys": {},
        }
    )
    user_key = os.urandom(16).hex()
    user_record_key = os.urandom(32)
    auth.save_user(
        user_key,
        {"username": "dana", "file_keys": [], "group_keys": {}},
        record_key=user_record_key,
    )
    auth.add_user_key_to_admin("dana", user_key, user_record_key.hex())

    assert auth.user_exists("dana") is True
    assert auth.user_exists("nope") is False

    # test get_admin_record returns None when missing and AdminUser when present
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path / "missing")
    assert auth.get_admin_record() is None
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    admin_key = auth.get_admin_key()
    auth.save_admin_record(
        {"username": "admin", "file_keys": {}, "group_keys": {}, "user_keys": {}},
    )
    admin = auth.get_admin_record()
    assert admin is not None
    assert getattr(admin, "user_keys", {}) == {}


def test_resolve_user_with_admin_index(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    # prepare user file and admin mapping
    auth.save_admin_record(
        {"username": "admin", "file_keys": {}, "group_keys": {}, "user_keys": {}}
    )
    key = os.urandom(16).hex()
    record_key = os.urandom(32)
    auth.save_user(
        key,
        {"username": "erin", "file_keys": [], "group_keys": {}},
        record_key=record_key,
    )
    auth.add_user_key_to_admin("erin", key, record_key.hex())

    admin = auth.get_admin_record()
    assert admin is not None

    user_key, user_dict = auth._resolve_user(admin, "erin")
    assert user_key == key
    assert user_dict is not None
    assert user_dict["username"] == "erin"


def test_create_user_creates_home_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(auth, "FILES_DIR", tmp_path)

    auth.create_user(auth.ADMIN, auth.ADMIN, is_admin=True)

    user_dict = auth.create_user("tester", "password", is_admin=False)
    assert user_dict is not None

    user_dir = tmp_path / hashlib.sha256("tester".encode("utf-8")).hexdigest()
    assert user_dir.exists() and user_dir.is_dir()


def test_create_admin_doesnt_create_home_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(auth, "FILES_DIR", tmp_path)

    user_dict = auth.create_user("tester", "password", is_admin=True)

    user_dir = tmp_path / "tester"
    assert not user_dir.exists() and not user_dir.is_dir()


def test_new_user_added_to_all_group(tmp_path, monkeypatch):
    """Test that new non-admin users are automatically added to the 'all' group."""
    import backend.group_utils as group_utils

    users_dir = tmp_path / ".users"
    groups_dir = tmp_path / ".groups"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    groups_dir.mkdir()
    files_dir.mkdir()

    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)
    monkeypatch.setattr(
        auth, "_user_file_path", lambda user_key: users_dir / f"{user_key}.json"
    )
    monkeypatch.setattr(
        auth, "create_user_directory", lambda username: files_dir / username
    )

    # Create admin first
    auth.create_user(auth.ADMIN, auth.ADMIN, is_admin=True)
    admin = auth.get_admin_record()
    assert admin is not None

    # Create the "all" group
    all_group = group_utils.create_group("all")
    assert all_group is not None

    # Create a new user
    user_dict = auth.create_user("testuser", "password123", is_admin=False)
    assert user_dict is not None

    # Verify user was added to "all" group
    all_group_loaded = group_utils.load_group("all")
    assert "testuser" in all_group_loaded["members"].values()

    # Verify user's group_keys includes the "all" group
    user_loaded = auth.load_user("testuser")
    admin_reloaded = auth.get_admin_record()
    all_group_path, _ = group_utils.get_group_access(admin_reloaded, "all")
    all_entry = user_loaded["group_keys"].get("all")
    assert isinstance(all_entry, dict)
    assert all_entry.get("file_path") == all_group_path
    assert isinstance(all_entry.get("encryption_key"), str)
    assert len(all_entry.get("encryption_key")) == 64


def test_admin_user_not_added_to_all_group(tmp_path, monkeypatch):
    """Test that admin users are NOT added to the 'all' group."""
    import backend.group_utils as group_utils

    users_dir = tmp_path / ".users"
    groups_dir = tmp_path / ".groups"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    groups_dir.mkdir()
    files_dir.mkdir()

    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)
    monkeypatch.setattr(
        auth, "_user_file_path", lambda user_key: users_dir / f"{user_key}.json"
    )

    # Create admin first
    admin_dict = auth.create_user(auth.ADMIN, auth.ADMIN, is_admin=True)
    admin = auth.get_admin_record()
    assert admin is not None

    # Create the "all" group
    all_group = group_utils.create_group("all")
    assert all_group is not None

    # Create another admin user
    admin2_dict = auth.create_user("admin2", "password123", is_admin=True)
    assert admin2_dict is not None

    # Verify admin2 was NOT added to "all" group
    all_group_loaded = group_utils.load_group("all")
    assert "admin2" not in all_group_loaded["members"].values()

    # Verify admin2's group_keys is a dict (admin format) and doesn't include groups as members
    admin2_loaded = auth.load_user("admin2")
    assert isinstance(admin2_loaded["group_keys"], dict)


def test_multiple_users_added_to_all_group(tmp_path, monkeypatch):
    """Test that multiple users are all added to the 'all' group."""
    import backend.group_utils as group_utils

    users_dir = tmp_path / ".users"
    groups_dir = tmp_path / ".groups"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    groups_dir.mkdir()
    files_dir.mkdir()

    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)
    monkeypatch.setattr(
        auth, "_user_file_path", lambda user_key: users_dir / f"{user_key}.json"
    )
    monkeypatch.setattr(
        auth, "create_user_directory", lambda username: files_dir / username
    )

    # Create admin and "all" group
    auth.create_user(auth.ADMIN, auth.ADMIN, is_admin=True)
    group_utils.create_group("all")

    # Create multiple users
    usernames = ["alice", "bob", "charlie"]
    for username in usernames:
        user_dict = auth.create_user(username, "password", is_admin=False)
        assert user_dict is not None

    # Verify all users are in the "all" group
    all_group = group_utils.load_group("all")
    for username in usernames:
        assert username in all_group["members"].values()


def test_create_user_creates_missing_all_group(tmp_path, monkeypatch):
    """User creation auto-creates missing 'all' group and adds the user."""
    import backend.group_utils as group_utils

    users_dir = tmp_path / ".users"
    groups_dir = tmp_path / ".groups"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    groups_dir.mkdir()
    files_dir.mkdir()

    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)
    monkeypatch.setattr(
        auth, "_user_file_path", lambda user_key: users_dir / f"{user_key}.json"
    )
    monkeypatch.setattr(
        auth, "create_user_directory", lambda username: files_dir / username
    )

    # Create admin but NOT the "all" group
    auth.create_user(auth.ADMIN, auth.ADMIN, is_admin=True)

    # Attempt to create a user without "all" group existing
    user_dict = auth.create_user("testuser", "password", is_admin=False)

    assert user_dict is not None
    all_group = group_utils.load_group("all")
    assert all_group is not None
    assert "testuser" in all_group["members"].values()
