import json

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
