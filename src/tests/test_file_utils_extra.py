from backend.file_utils import (add_file_to_group, add_file_to_user,
                                check_user_file_integrities,
                                remove_file_tracking_for_user,
                                sync_file_info_for_user)
from models.directory import Directory
from models.file import File
from models.group import Group
from tests.tamper_helpers import (flip_last_gcm_tag_nibble,
                                  flip_last_hash_nibble)
from tests.test_helpers import make_user


def make_group(tmp_path, name="dev"):
    group = Group(
        group_name=name,
        encrypted_name=name,
        members={},
        file_access={},
        path=tmp_path / f"{name}.json",
    )
    key = b"\x03" * 32
    group.save(key)
    group._test_key = key
    return group


def test_add_file_to_user_normalizes_bytes_key(tmp_path):
    user = make_user(tmp_path, "alice")
    assert add_file_to_user("notes", user, b"secret") is True
    assert user.file_keys["notes"] == b"secret".hex()


def test_add_file_to_group_stores_access_entry(tmp_path):
    user = make_user(tmp_path, "alice")
    group = make_group(tmp_path, "dev")
    file = File.create(tmp_path, "notes", user)
    assert (
        add_file_to_group(
            group, bytes.fromhex("ab" * 32), file, file.encrypted_file_key
        )
        is True
    )
    entry = group.file_access[str(file.path)]
    assert entry["name"] == "notes"
    assert entry["owner"] == "alice"


def test_check_user_file_integrities_reports_missing_and_tampered_files(tmp_path):
    user = make_user(tmp_path, "alice")
    home = Directory.create(tmp_path, "alice", user)
    file1 = File.create(home.path, "file1.txt", user, body="hello")
    subdir = Directory.create(home.path, "subdir", user)
    file2 = File.create(subdir.path, "file2.txt", user, body="nested")
    missing = File.create(home.path, "missing.txt", user, body="gone")
    missing.path.unlink()
    flip_last_hash_nibble(file1.path)
    flip_last_gcm_tag_nibble(file2.path)

    compromised = check_user_file_integrities(user, home.path)

    assert "alice/file1.txt" in compromised
    assert "alice/subdir/file2.txt" in compromised
    assert "alice/missing.txt" in compromised


def test_sync_file_info_for_user_keeps_decrypted_name(tmp_path):
    user = make_user(tmp_path, "alice")
    home = Directory.create(tmp_path, "alice", user)
    file = File.create(home.path, "notes.txt", user, body="start")
    file.body = "changed"
    file.save()

    assert sync_file_info_for_user(user, file) is True
    assert user.file_info[str(file.path)] == "notes.txt"


def test_remove_file_tracking_for_user_drops_stale_entries(tmp_path):
    user = make_user(tmp_path, "alice")
    home = Directory.create(tmp_path, "alice", user)
    file = File.create(home.path, "old.txt", user, body="content")

    assert str(file.path) in user.file_keys
    assert str(file.path) in user.file_info
    assert remove_file_tracking_for_user(user, file.path) is True
    assert str(file.path) not in user.file_keys
    assert str(file.path) not in user.file_info
