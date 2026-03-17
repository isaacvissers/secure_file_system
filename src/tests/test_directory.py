import json
from hashlib import sha256

import pytest

from models.directory import Directory
from models.file import File, Permission
from tests.test_helpers import make_user


def test_directory_create_returns_directory_instance(tmp_path):
    user = make_user(tmp_path, "owner")
    directory = Directory.create(tmp_path, "mydir", user)
    assert isinstance(directory, Directory)


def test_directory_create_sets_path(tmp_path):
    user = make_user(tmp_path, "owner")
    directory = Directory.create(tmp_path, "mydir", user)
    assert directory.path == tmp_path / sha256("mydir".encode("utf-8")).hexdigest()


def test_directory_create_creates_dir_on_disk(tmp_path):
    user = make_user(tmp_path, "owner")
    Directory.create(tmp_path, "newdir", user)
    assert (tmp_path / sha256("newdir".encode("utf-8")).hexdigest()).is_dir()


def test_directory_create_raises_when_already_exists(tmp_path):
    user = make_user(tmp_path, "owner")
    (tmp_path / sha256("exists".encode("utf-8")).hexdigest()).mkdir()
    with pytest.raises(FileExistsError):
        Directory.create(tmp_path, "exists", user)


def test_directory_create_attaches_metadata(tmp_path):
    user = make_user(tmp_path, "owner")
    directory = Directory.create(tmp_path, "docs", user)
    assert isinstance(directory.metadata, File)


def test_directory_metadata_file_name(tmp_path):
    user = make_user(tmp_path, "owner")
    directory = Directory.create(tmp_path, "docs", user)
    assert directory.metadata.file_name == "docs"


def test_directory_metadata_written_to_dotfile(tmp_path):
    user = make_user(tmp_path, "owner")
    Directory.create(tmp_path, "archive", user)
    meta_file = tmp_path / f".{sha256('archive'.encode('utf-8')).hexdigest()}"
    assert meta_file.exists()


def test_directory_metadata_json_is_valid(tmp_path):
    user = make_user(tmp_path, "owner")
    directory = Directory.create(tmp_path, "archive", user)
    loaded = File.get_file(
        directory.metadata.path, directory.metadata.encrypted_file_key
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


def test_directory_metadata_permission_default(tmp_path):
    user = make_user(tmp_path, "owner")
    directory = Directory.create(tmp_path, "priv", user)
    assert directory.metadata.permission == Permission.USER
