import json

import pytest

from models.directory import Directory
from models.file import File, Permission

# ---------------------------------------------------------------------------
# Directory.create()
# ---------------------------------------------------------------------------


def test_directory_create_returns_directory_instance(tmp_path):
    """Directory.create() returns a Directory object."""
    d = Directory.create(tmp_path, "mydir", "owner")
    assert isinstance(d, Directory)


def test_directory_create_sets_path(tmp_path):
    """Directory.create() sets path to working_dir / name."""
    d = Directory.create(tmp_path, "mydir", "owner")
    assert d.path == tmp_path / "mydir"


def test_directory_create_creates_dir_on_disk(tmp_path):
    """Directory.create() creates the directory on the filesystem."""
    Directory.create(tmp_path, "newdir", "owner")
    assert (tmp_path / "newdir").is_dir()


def test_directory_create_raises_when_already_exists(tmp_path):
    """Directory.create() raises an OSError if the directory already exists."""
    (tmp_path / "exists").mkdir()
    with pytest.raises(OSError):
        Directory.create(tmp_path, "exists", "owner")


# ---------------------------------------------------------------------------
# Directory metadata (File)
# ---------------------------------------------------------------------------


def test_directory_create_attaches_metadata(tmp_path):
    """Directory.create() attaches a File instance as metadata."""
    d = Directory.create(tmp_path, "docs", "owner")
    assert isinstance(d.metadata, File)


def test_directory_metadata_file_name(tmp_path):
    """Directory metadata records the directory name."""
    d = Directory.create(tmp_path, "docs", "owner")
    assert d.metadata.file_name == "dir_docs"


def test_directory_metadata_written_to_json(tmp_path):
    """Directory.create() writes a JSON metadata file alongside the directory."""
    Directory.create(tmp_path, "archive", "owner")
    meta_file = tmp_path / "dir_archive"
    assert meta_file.exists()


def test_directory_metadata_json_is_valid(tmp_path):
    """The encrypted metadata file decrypts to valid JSON with expected keys."""
    directory = Directory.create(tmp_path, "archive", "owner")
    loaded = File.get_file(
        tmp_path / "dir_archive", directory.metadata.encrypted_file_key
    )
    data = json.loads(loaded.to_json())
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


def test_directory_metadata_file_name_in_json(tmp_path):
    """The decrypted metadata file_name matches the directory name."""
    directory = Directory.create(tmp_path, "archive", "owner")
    loaded = File.get_file(
        tmp_path / "archive.json", directory.metadata.encrypted_file_key
    )
    assert loaded.file_name == "archive"


def test_directory_metadata_permission_default(tmp_path):
    """Default permission is USER."""
    d = Directory.create(tmp_path, "priv", "owner")
    assert d.metadata.permission == Permission.USER
