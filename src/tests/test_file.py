import hashlib
import json

import pytest

from backend.file_utils import add_file_to_user
from models.directory import Directory
from models.file import File, Permission
from tests.test_helpers import make_user


def _load_created_file(file: File) -> File:
    return File.get_file(file.path, file.encrypted_file_key)


def test_file_create_returns_file_instance(tmp_path):
    user = make_user(tmp_path, "owner")
    file = File.create(tmp_path, "notes", user)
    assert isinstance(file, File)


def test_file_create_sets_file_name(tmp_path):
    user = make_user(tmp_path, "owner")
    assert File.create(tmp_path, "notes", user).file_name == "notes"


def test_file_create_sets_path_to_hashed_name(tmp_path):
    user = make_user(tmp_path, "owner")
    file = File.create(tmp_path, "notes", user)
    assert file.path == tmp_path / hashlib.sha256("notes".encode("utf-8")).hexdigest()


def test_file_create_writes_file_to_disk(tmp_path):
    user = make_user(tmp_path, "owner")
    File.create(tmp_path, "notes", user)
    assert (tmp_path / hashlib.sha256("notes".encode("utf-8")).hexdigest()).exists()


def test_file_create_writes_encrypted_payload(tmp_path):
    user = make_user(tmp_path, "owner")
    file = File.create(tmp_path, "notes", user)
    payload = file.path.read_bytes()
    assert len(payload) > 12
    assert payload != file.to_json().encode("utf-8")


def test_file_create_can_be_loaded_from_disk(tmp_path):
    user = make_user(tmp_path, "owner")
    file = File.create(tmp_path, "notes", user)
    assert _load_created_file(file).file_name == "notes"


def test_file_create_json_has_expected_keys(tmp_path):
    user = make_user(tmp_path, "owner")
    data = json.loads(File.create(tmp_path, "notes", user).to_json())
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


def test_file_create_default_permission_is_user(tmp_path):
    user = make_user(tmp_path, "owner")
    assert File.create(tmp_path, "notes", user).permission == Permission.USER


def test_file_create_raises_when_file_already_exists(tmp_path):
    user = make_user(tmp_path, "owner")
    (tmp_path / hashlib.sha256("duplicate".encode("utf-8")).hexdigest()).write_bytes(
        b"{}"
    )
    with pytest.raises(FileExistsError):
        File.create(tmp_path, "duplicate", user)


def test_file_create_encrypted_name_is_deterministic_hash(tmp_path):
    user = make_user(tmp_path, "owner")
    file = File.create(tmp_path, "secret", user)
    assert file.encrypted_name == hashlib.sha256("secret".encode("utf-8")).hexdigest()


def test_to_json_is_valid_json(tmp_path):
    user = make_user(tmp_path, "owner")
    data = json.loads(File.create(tmp_path, "doc", user).to_json())
    assert isinstance(data, dict)
    assert data["file_name"] == "doc"
    assert data["permission"] == "user"


def test_add_file_to_user_stores_hex_for_bytes(tmp_path):
    user = make_user(tmp_path, "bob")
    result = add_file_to_user("notes", user, b"secretname")
    assert result is True
    assert user.file_keys["notes"] == b"secretname".hex()


def test_add_file_to_user_with_directory_metadata_key(tmp_path):
    user = make_user(tmp_path, "carol")
    directory = Directory.create(tmp_path, "docs", user)

    result = add_file_to_user(str(directory.metadata.path), user, directory)

    assert result is True
    assert (
        user.file_keys[str(directory.metadata.path)]
        == directory.metadata.encrypted_name
    )
