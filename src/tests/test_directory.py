import pytest

from models.file import Directory


def test_directory_create_returns_directory_instance(tmp_path):
    """Directory.create() returns a Directory object."""
    d = Directory.create(tmp_path, "mydir")
    assert isinstance(d, Directory)


def test_directory_create_sets_file_name(tmp_path):
    """Directory.create() sets file_name to the provided name."""
    d = Directory.create(tmp_path, "mydir")
    assert d.file_name == "mydir"


def test_directory_create_sets_path(tmp_path):
    """Directory.create() sets path to working_dir / name."""
    d = Directory.create(tmp_path, "mydir")
    assert d.path == tmp_path / "mydir"


def test_directory_create_creates_dir_on_disk(tmp_path):
    """Directory.create() creates the directory on the filesystem."""
    Directory.create(tmp_path, "newdir")
    assert (tmp_path / "newdir").is_dir()


def test_directory_create_raises_when_already_exists(tmp_path):
    """Directory.create() raises an OSError if the directory already exists."""
    (tmp_path / "exists").mkdir()
    with pytest.raises(OSError):
        Directory.create(tmp_path, "exists")
