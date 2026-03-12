import hashlib
import json

import pytest

from models.directory import Directory
from models.file import File, Permission


def _load_created_file(file: File) -> File:
    return File.get_file(file.path, file.encrypted_file_key)


def test_file_create_returns_file_instance(tmp_path):
    f = File.create(tmp_path, "notes", "owner")
    assert isinstance(f, File)


def test_file_create_sets_file_name(tmp_path):
    f = File.create(tmp_path, "notes", "owner")
    assert f.file_name == "notes"


def test_file_create_sets_path_to_json_file(tmp_path):
    f = File.create(tmp_path, "notes", "owner")
    assert f.path == tmp_path / "notes.json"


def test_file_create_writes_file_to_disk(tmp_path):
    File.create(tmp_path, "notes", "owner")
    assert (tmp_path / "notes.json").exists()


def test_file_create_writes_encrypted_payload(tmp_path):
    f = File.create(tmp_path, "notes", "owner")
    payload = f.path.read_bytes()
    assert len(payload) > 12
    assert payload != f.to_json().encode("utf-8")


def test_file_create_can_be_loaded_from_disk(tmp_path):
    f = File.create(tmp_path, "notes", "owner")
    loaded = _load_created_file(f)
    assert loaded.file_name == "notes"


def test_file_create_json_has_expected_keys(tmp_path):
    f = File.create(tmp_path, "notes", "owner")
    data = json.loads(f.to_json())
    for key in (
        "file_name",
        "owner_name",
        "permission",
        "encrypted_name",
        "body",
        "encrypted_file_key",
        "path",
    ):
        assert key in data


def test_file_create_json_file_name_matches(tmp_path):
    f = File.create(tmp_path, "report", "owner")
    data = json.loads(f.to_json())
    assert data["file_name"] == "report"


def test_file_create_default_permission_is_user(tmp_path):
    f = File.create(tmp_path, "notes", "owner")
    assert f.permission == Permission.USER


def test_file_create_default_permission_in_json(tmp_path):
    f = File.create(tmp_path, "notes", "owner")
    data = json.loads(f.to_json())
    assert data["permission"] == "user"


def test_file_create_raises_when_file_already_exists(tmp_path):
    (tmp_path / "duplicate.json").write_bytes(b"{}")
    with pytest.raises(FileExistsError):
        File.create(tmp_path, "duplicate", "owner")


def test_file_create_encrypted_fields_are_hex_strings(tmp_path):
    f = File.create(tmp_path, "secret", "owner")
    data = json.loads(f.to_json())
    bytes.fromhex(data["encrypted_name"])
    bytes.fromhex(data["encrypted_file_key"])


def test_file_create_encrypted_name_is_deterministic_hash(tmp_path):
    f = File.create(tmp_path, "secret", "owner")
    expected_hash = hashlib.sha256(str(f.path).encode("utf-8")).hexdigest()
    assert f.encrypted_name == expected_hash


def test_to_json_returns_string(tmp_path):
    f = File.create(tmp_path, "doc", "owner")
    assert isinstance(f.to_json(), str)


def test_to_json_is_valid_json(tmp_path):
    f = File.create(tmp_path, "doc", "owner")
    data = json.loads(f.to_json())
    assert isinstance(data, dict)


def test_to_json_file_name_matches(tmp_path):
    f = File.create(tmp_path, "doc", "owner")
    data = json.loads(f.to_json())
    assert data["file_name"] == "doc"


def test_to_json_permission_is_serialised(tmp_path):
    f = File.create(tmp_path, "doc", "owner")
    data = json.loads(f.to_json())
    assert data["permission"] == f.permission.value


def test_add_file_to_user_stores_hex_for_bytes(tmp_path, monkeypatch):
    import backend.auth as auth
    import backend.group_utils as group_utils
    from backend.file_utils import add_file_to_user

    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    groups_dir = tmp_path / "groups"
    users_dir.mkdir()
    files_dir.mkdir()
    groups_dir.mkdir()
    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)

    admin_key = auth.get_admin_key()
    admin_record = {
        "username": "admin",
        "file_keys": {},
        "user_keys": {},
        "group_keys": {},
    }
    auth.save_user(admin_key, admin_record)
    group_utils.create_group("all")

    created = auth.create_user("bob", "pw", is_admin=False)
    assert created is not None

    b = b"secretname"
    res = add_file_to_user("notes", b, "bob")
    assert res is True

    user = auth.load_user("bob")
    assert user is not None
    assert user.get("file_keys", {}).get("notes") == b.hex()


def test_add_file_to_user_with_directory_object(tmp_path, monkeypatch):
    import backend.auth as auth
    import backend.group_utils as group_utils
    from backend.file_utils import add_file_to_user

    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    groups_dir = tmp_path / "groups"
    users_dir.mkdir()
    files_dir.mkdir()
    groups_dir.mkdir()
    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)

    admin_key = auth.get_admin_key()
    admin_record = {
        "username": "admin",
        "file_keys": {},
        "user_keys": {},
        "group_keys": {},
    }
    auth.save_user(admin_key, admin_record)
    group_utils.create_group("all")

    created = auth.create_user("carol", "pw", is_admin=False)
    assert created is not None

    user_home = files_dir / "carol"
    user_home.mkdir(exist_ok=True)
    directory = Directory.create(files_dir / "carol", "docs", "carol")

    res = add_file_to_user("docs", directory, "carol")
    assert res is True

    user = auth.load_user("carol")
    assert user is not None
    assert user.get("file_keys", {}).get("docs") == directory.metadata.encrypted_name
