import hashlib
import json

from tests.tamper_helpers import flip_last_gcm_tag_nibble, flip_last_hash_nibble


def test_get_user_file_keys_and_add_file_to_group_propagation(tmp_path, monkeypatch):
    """Adding a file to a user should store the normalized key and propagate to groups."""
    import backend.auth as auth
    from backend.file_utils import (
        add_file_to_user,
        add_file_to_user_and_groups,
        get_user_file_keys,
    )
    from backend.group_utils import add_user_to_group, create_group, load_group

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
    directory = Directory.create(files_dir / "carol", "docs", "carol")

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
    from backend.file_utils import add_file_to_group
    from backend.group_utils import create_group, load_group

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


def test_check_user_file_integrities_reports_decrypted_and_encrypted_paths(
    tmp_path, monkeypatch
):
    """Integrity scan should recurse owned files and fall back to encrypted names on decrypt failure."""
    import backend.auth as auth
    import backend.group_utils as group_utils
    from backend.file_utils import check_user_file_integrities
    from models.directory import Directory
    from models.file import File

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
    assert auth.create_user("alice", "pw", is_admin=False) is not None

    home = files_dir / hashlib.sha256("alice".encode("utf-8")).hexdigest()
    file1 = File.create(home, "file1.txt", "alice", body="hello")
    subdir = Directory.create(home, "subdir", "alice")
    file2 = File.create(subdir.path, "file2.txt", "alice", body="nested")
    missing_file = File.create(home, "missing.txt", "alice", body="gone")
    missing_file.path.unlink()

    # Tamper only with the trailing stored hash so decryption still succeeds.
    flip_last_hash_nibble(file2.path)
    assert File.get_file(file2.path, file2.encrypted_file_key).file_name == "file2.txt"

    user = auth.load_user("alice")
    assert user is not None

    # Force decrypt failure for file1 so output falls back to encrypted leaf name.
    user["file_keys"][str(file1.path)] = "not-hex"

    compromised = check_user_file_integrities(user, home)

    assert f"alice/subdir/file2.txt" in compromised
    assert f"alice/{file1.path.name}" in compromised
    assert f"alice/{missing_file.path.name}" in compromised


def test_check_user_file_integrities_recovers_name_on_invalid_tag(
    tmp_path, monkeypatch
):
    """If tag verification fails, compromised output should still try to show decrypted file name."""
    import backend.auth as auth
    import backend.group_utils as group_utils
    from backend.file_utils import check_user_file_integrities
    from models.file import File

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
    assert auth.create_user("alice", "pw", is_admin=False) is not None

    home = files_dir / hashlib.sha256("alice".encode("utf-8")).hexdigest()
    file1 = File.create(home, "test.txt", "alice", body="original")

    # Corrupt only the GCM tag nibble: authenticated decrypt should fail,
    # but tentative plaintext can still be parsed for display-only recovery.
    flip_last_gcm_tag_nibble(file1.path)

    user = auth.load_user("alice")
    assert user is not None
    compromised = check_user_file_integrities(user, home)

    assert "alice/test.txt" in compromised
    assert f"alice/{file1.path.name}" not in compromised


def test_check_user_file_integrities_salvages_name_from_partial_plaintext(
    tmp_path, monkeypatch
):
    """Even if JSON parse fails, scan plaintext for file_name and use it for warning display."""
    import backend.auth as auth
    import backend.group_utils as group_utils
    import backend.file_utils as file_utils
    from backend.file_utils import check_user_file_integrities
    from models.file import File

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
    assert auth.create_user("alice", "pw", is_admin=False) is not None

    home = files_dir / hashlib.sha256("alice".encode("utf-8")).hexdigest()
    file1 = File.create(home, "test.txt", "alice", body="original")

    user = auth.load_user("alice")
    assert user is not None

    original_recover = file_utils._recover_file_name_unverified

    def fake_recover(path, key_hex):
        _ = path
        _ = key_hex
        # Simulate partially corrupted plaintext where full JSON parse fails,
        # but file_name remains present for regex salvage.
        tentative = '{\n  "file_name": "test.txt",\n  "owner_name": \x00\n}'
        import json as _json
        import re as _re

        try:
            _json.loads(tentative)
        except Exception:
            m = _re.search(r'"file_name"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', tentative)
            if m:
                return m.group(1)
        return None

    monkeypatch.setattr(file_utils, "_recover_file_name_unverified", fake_recover)

    # Force authenticated decrypt failure so the fallback path is used.
    user["file_keys"][str(file1.path)] = "not-hex"
    # Also mark the file compromised via hash mismatch so it appears in output.
    flip_last_hash_nibble(file1.path)
    compromised = check_user_file_integrities(user, home)

    monkeypatch.setattr(file_utils, "_recover_file_name_unverified", original_recover)

    assert "alice/test.txt" in compromised
