import json
import hashlib

import pytest

from models.file import File, Permission

# ---------------------------------------------------------------------------
# File.create()
# ---------------------------------------------------------------------------


def test_file_create_returns_file_instance(tmp_path):
    """File.create() returns a File object."""
    f = File.create(tmp_path, "notes")
    assert isinstance(f, File)


def test_file_create_sets_file_name(tmp_path):
    """File.create() sets file_name to the provided name."""
    f = File.create(tmp_path, "notes")
    assert f.file_name == "notes"


def test_file_create_sets_path_to_json_file(tmp_path):
    """File.create() sets path to working_dir / <name>.json."""
    f = File.create(tmp_path, "notes")
    assert f.path == tmp_path / "notes.json"


def test_file_create_writes_json_to_disk(tmp_path):
    """File.create() writes a .json file on disk."""
    File.create(tmp_path, "notes")
    assert (tmp_path / "notes.json").exists()


def test_file_create_json_is_valid(tmp_path):
    """The written JSON file contains valid JSON."""
    File.create(tmp_path, "notes")
    data = json.loads((tmp_path / "notes.json").read_text())
    assert isinstance(data, dict)


def test_file_create_json_has_expected_keys(tmp_path):
    """The written JSON contains all expected metadata keys."""
    File.create(tmp_path, "notes")
    data = json.loads((tmp_path / "notes.json").read_text())
    for key in (
        "file_name",
        "owner_name",
        "permission",
        "encrypted_name",
        "encrypted_body",
        "encrypted_file_key",
        "path",
    ):
        assert key in data


def test_file_create_json_file_name_matches(tmp_path):
    """The file_name field in JSON matches the name passed to create()."""
    File.create(tmp_path, "report")
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["file_name"] == "report"


def test_file_create_default_permission_is_user(tmp_path):
    """Default permission is Permission.USER."""
    f = File.create(tmp_path, "notes")
    assert f.permission == Permission.USER


def test_file_create_default_permission_in_json(tmp_path):
    """JSON records the permission as 'user'."""
    File.create(tmp_path, "notes")
    data = json.loads((tmp_path / "notes.json").read_text())
    assert data["permission"] == "user"


def test_file_create_raises_when_file_already_exists(tmp_path):
    """File.create() raises FileExistsError when the .json file already exists."""
    (tmp_path / "duplicate.json").write_text("{}")
    with pytest.raises(FileExistsError):
        File.create(tmp_path, "duplicate")


def test_file_create_encrypted_fields_are_hex_strings(tmp_path):
    """encrypted_name, encrypted_body, encrypted_file_key are hex strings in JSON."""
    File.create(tmp_path, "secret")
    data = json.loads((tmp_path / "secret.json").read_text())
    for field in ("encrypted_name", "encrypted_body", "encrypted_file_key"):
        # Should be a valid hex string (no exception)
        bytes.fromhex(data[field])


def test_file_create_encrypted_name_is_deterministic_hash(tmp_path):
    """encrypted_name is a deterministic one-way hash of file_name."""
    File.create(tmp_path, "secret")
    data = json.loads((tmp_path / "secret.json").read_text())

    expected_hash = hashlib.sha256(data["file_name"].encode("utf-8")).hexdigest()

    assert data["encrypted_name"] == expected_hash


# ---------------------------------------------------------------------------
# File.to_json()
# ---------------------------------------------------------------------------


def test_to_json_returns_string(tmp_path):
    """to_json() returns a string."""
    f = File.create(tmp_path, "doc")
    assert isinstance(f.to_json(), str)


def test_to_json_is_valid_json(tmp_path):
    """to_json() output parses as valid JSON."""
    f = File.create(tmp_path, "doc")
    data = json.loads(f.to_json())
    assert isinstance(data, dict)


def test_to_json_file_name_matches(tmp_path):
    """to_json() includes the correct file_name."""
    f = File.create(tmp_path, "doc")
    data = json.loads(f.to_json())
    assert data["file_name"] == "doc"


def test_to_json_permission_is_serialised(tmp_path):
    """to_json() serialises permission as its string value."""
    f = File.create(tmp_path, "doc")
    data = json.loads(f.to_json())
    assert data["permission"] == f.permission.value


# ---------------------------------------------------------------------------
# file_utils.add_file_to_user
# ---------------------------------------------------------------------------


def test_add_file_to_user_stores_hex_for_bytes(tmp_path, monkeypatch):
    """Passing raw bytes stores a hex string in the user's file_keys."""
    import backend.auth as auth
    import backend.group_utils as group_utils
    from backend.file_utils import add_file_to_user

    # isolate storage to tmp_path
    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    groups_dir = tmp_path / "groups"
    users_dir.mkdir()
    files_dir.mkdir()
    groups_dir.mkdir()
    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)

    # create an admin record so create_user can update the admin index
    admin_key = auth.get_admin_key()
    admin_record = {
        "username": "admin",
        "file_keys": [],
        "user_keys": {},
        "group_keys": {},
    }
    auth.save_user(admin_key, admin_record)
    group_utils.create_group("all")

    # create a normal user
    created = auth.create_user("bob", "pw", is_admin=False)
    assert created is not None

    # add raw bytes
    b = b"secretname"
    res = add_file_to_user(b, "bob")
    assert res is True

    user = auth.load_user("bob")
    assert user is not None
    # hex of 'secretname'
    assert b.hex() in user.get("file_keys", [])


def test_add_file_to_user_with_directory_object(tmp_path, monkeypatch):
    """Passing a Directory object stores its metadata.encrypted_name hex."""
    import backend.auth as auth
    import backend.group_utils as group_utils
    from backend.file_utils import add_file_to_user
    from models.directory import Directory

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
        "file_keys": [],
        "user_keys": {},
        "group_keys": {},
    }
    auth.save_user(admin_key, admin_record)
    group_utils.create_group("all")

    created = auth.create_user("carol", "pw", is_admin=False)
    assert created is not None

    # create a directory in the user's files area
    user_home = files_dir / "carol"
    # Directory.create expects the parent dir to exist
    user_home.mkdir(exist_ok=True)
    directory = Directory.create(files_dir / "carol", "docs")

    res = add_file_to_user(directory, "carol")
    assert res is True

    user = auth.load_user("carol")
    assert user is not None
    # directory.metadata.encrypted_name as hex should be present
    enc = directory.metadata.encrypted_name
    assert isinstance(enc, (bytes, bytearray))
    assert enc.hex() in user.get("file_keys", [])
