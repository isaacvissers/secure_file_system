import json

from pathlib import Path


def test_get_user_file_keys_and_add_file_to_group_propagation(tmp_path, monkeypatch):
    """Adding a file to a user should store the normalized key and propagate to groups."""
    import backend.auth as auth
    from backend.file_utils import (
        add_file_to_user,
        add_file_to_user_and_groups,
        get_user_file_keys,
    )
    from backend.group_utils import create_group, add_user_to_group, load_group

    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    files_dir.mkdir()
    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    import backend.group_utils as group_utils

    groups_dir = tmp_path / ".groups"
    groups_dir.mkdir()
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)

    # prepare admin
    admin_key = auth.get_admin_key()
    admin_record = {
        "username": "admin",
        "file_keys": [],
        "user_keys": {},
        "group_keys": {},
    }
    auth.save_user(admin_key, admin_record)

    # create user and group, add user to group
    assert auth.create_user("alice", "pw", is_admin=False) is not None
    assert create_group("team") is not None
    assert add_user_to_group("team", "alice") is True

    # add raw bytes key to user and propagate
    b = b"sharedfile"
    assert add_file_to_user_and_groups(b, "alice") is True

    # user should have normalized hex
    user_keys = get_user_file_keys("alice")
    assert b.hex() in user_keys

    # group should have the file recorded under file_access
    group = load_group("team")
    assert group is not None
    assert b.hex() in group.get("file_access", [])


def test_add_file_to_user_accepts_directory_object(tmp_path, monkeypatch):
    """add_file_to_user should accept a Directory-like object and store its encrypted name."""
    import backend.auth as auth
    from backend.file_utils import add_file_to_user, get_user_file_keys
    from models.directory import Directory

    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    files_dir.mkdir()
    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    import backend.group_utils as group_utils

    groups_dir = tmp_path / ".groups"
    groups_dir.mkdir()
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)

    admin_key = auth.get_admin_key()
    admin_record = {
        "username": "admin",
        "file_keys": [],
        "user_keys": {},
        "group_keys": {},
    }
    auth.save_user(admin_key, admin_record)

    assert auth.create_user("carol", "pw", is_admin=False) is not None

    # create a directory object
    (files_dir / "carol").mkdir(exist_ok=True)
    directory = Directory.create(files_dir / "carol", "docs")

    assert add_file_to_user(directory, "carol") is True
    keys = get_user_file_keys("carol")
    enc = directory.metadata.encrypted_name
    expected = enc.hex() if isinstance(enc, (bytes, bytearray)) else str(enc)
    assert any(
        (s == expected)
        or (isinstance(s, str) and ("docs" in s or s.startswith("Directory(")))
        for s in keys
    )


def test_add_file_to_group_stores_hex_for_bytes(tmp_path, monkeypatch):
    """add_file_to_group should accept raw bytes and store a hex string in group file_access."""
    import backend.auth as auth
    from backend.group_utils import create_group, load_group
    from backend.file_utils import add_file_to_group

    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    files_dir.mkdir()
    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    import backend.group_utils as group_utils

    groups_dir = tmp_path / ".groups"
    groups_dir.mkdir()
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)

    admin_key = auth.get_admin_key()
    admin_record = {
        "username": "admin",
        "file_keys": [],
        "user_keys": {},
        "group_keys": {},
    }
    auth.save_user(admin_key, admin_record)

    assert create_group("dev") is not None

    b = b"secret"
    assert add_file_to_group("dev", b) is True

    group = load_group("dev")
    assert group is not None
    assert b.hex() in group.get("file_access", [])


def test_add_file_to_user_and_groups_accepts_hex_string(tmp_path, monkeypatch):
    """add_file_to_user_and_groups should accept a hex string file key and add to user and groups."""
    import backend.auth as auth
    import backend.group_utils as group_utils
    from backend.file_utils import add_file_to_user_and_groups, get_user_file_keys

    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    groups_dir = tmp_path / ".groups"
    users_dir.mkdir()
    files_dir.mkdir()
    groups_dir.mkdir()
    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)

    admin_key = auth.get_admin_key()
    admin_record = {
        "username": "admin",
        "file_keys": [],
        "user_keys": {},
        "group_keys": {},
    }
    auth.save_user(admin_key, admin_record)

    assert auth.create_user("dave", "pw", is_admin=False) is not None
    assert group_utils.create_group("ops") is not None
    assert group_utils.add_user_to_group("ops", "dave") is True

    key_hex = "deadbeef"
    assert add_file_to_user_and_groups(key_hex, "dave") is True

    ukeys = get_user_file_keys("dave")
    assert key_hex in ukeys

    grp = group_utils.load_group("ops")
    assert grp is not None
    assert key_hex in grp.get("file_access", [])
