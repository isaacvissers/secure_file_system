import hashlib
import os
from pathlib import Path

from models.directory import Directory
from models.file import File
from models.group import Group
from tests.encryption_helpers import load_tracked_file, track_file
from tests.path_helpers import encrypted_path
from tests.test_helpers import make_logged_in_shell, make_user


def _logged_in_shell(tmp_path, monkeypatch, username="alice"):
    return make_logged_in_shell(tmp_path, monkeypatch, username=username)


def _attach_group(shell, tmp_path, group_name):
    group_key = os.urandom(32)
    encrypted_name = hashlib.sha256(group_name.encode("utf-8")).hexdigest()
    group_path = tmp_path / f"{group_name}.group"
    group = Group(
        group_name=group_name,
        encrypted_name=encrypted_name,
        members={},
        file_access={},
        path=group_path,
    )
    group.save(group_key)
    shell.current_user.group_keys[group_name] = {
        "id": str(group_path),
        "key": group_key.hex(),
    }
    shell.current_user.save(shell.current_user_key)
    return group_path, group_key


def test_set_permissions_to_user(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = encrypted_path(shell.current_working_directory, "test")
    track_file(
        shell, File.create(shell.current_working_directory, "test", shell.current_user)
    )
    shell.do_set_permissions("test user")
    assert load_tracked_file(shell, file_path).permission.value == "user"


def test_set_permissions_to_group(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = encrypted_path(shell.current_working_directory, "test")
    track_file(
        shell, File.create(shell.current_working_directory, "test", shell.current_user)
    )
    shell.do_set_permissions("test group")
    assert load_tracked_file(shell, file_path).permission.value == "group"


def test_set_permissions_to_all(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = encrypted_path(shell.current_working_directory, "test")
    track_file(
        shell, File.create(shell.current_working_directory, "test", shell.current_user)
    )
    shell.do_set_permissions("test all")
    assert load_tracked_file(shell, file_path).permission.value == "all"


def test_set_permissions_file_not_found(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_set_permissions("nonexistent user")
    assert "does not exist" in capsys.readouterr().out


def test_set_permissions_invalid_permission_value(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(
        shell, File.create(shell.current_working_directory, "test", shell.current_user)
    )
    shell.do_set_permissions("test invalid")
    out = capsys.readouterr().out
    assert "Invalid permissions format" in out
    assert "user" in out and "group" in out and "all" in out


def test_set_permissions_wrong_number_of_args(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_set_permissions("test")
    assert "Invalid syntax" in capsys.readouterr().out


def test_set_permissions_not_owner(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch, username="alice")
    bob = make_user(tmp_path, "bob")
    bob_home = Directory.create(tmp_path, "bob", bob)
    file = File.create(bob_home.path, "test", bob)
    shell.current_user.file_keys[str(file.path)] = file.encrypted_file_key.hex()
    shell.current_working_directory = bob_home.path
    shell.do_set_permissions("test user")
    assert "not the owner" in capsys.readouterr().out


def test_set_permissions_recursive_updates_subtree(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    project = Directory.create(
        shell.current_working_directory, "project", shell.current_user
    )
    track_file(shell, project.metadata)
    readme = File.create(project.path, "readme", shell.current_user)
    track_file(shell, readme)
    docs = Directory.create(project.path, "docs", shell.current_user)
    track_file(shell, docs.metadata)
    notes = File.create(docs.path, "notes", shell.current_user)
    track_file(shell, notes)

    shell.do_set_permissions("project all -r")

    for path in [project.metadata.path, readme.path, docs.metadata.path, notes.path]:
        assert load_tracked_file(shell, path).permission.value == "all"


def test_get_permissions_returns_updated_value(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(
        shell, File.create(shell.current_working_directory, "test", shell.current_user)
    )
    shell.do_set_permissions("test group")
    capsys.readouterr()
    shell.do_get_permissions("test")
    assert "group" in capsys.readouterr().out


def test_set_permissions_all_to_group_moves_group_access(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    all_group_path, all_group_key = _attach_group(shell, tmp_path, "all")
    dev_group_path, dev_group_key = _attach_group(shell, tmp_path, "dev")
    ops_group_path, ops_group_key = _attach_group(shell, tmp_path, "ops")

    file = File.create(shell.current_working_directory, "report", shell.current_user)
    track_file(shell, file)

    shell.do_set_permissions("report all")
    shell.do_set_permissions("report group")

    all_group = Group.get_group(all_group_path, all_group_key)
    dev_group = Group.get_group(dev_group_path, dev_group_key)
    ops_group = Group.get_group(ops_group_path, ops_group_key)
    file_id = str(file.path)

    assert file_id not in all_group.file_access
    assert file_id in dev_group.file_access
    assert file_id in ops_group.file_access


def test_set_permissions_group_to_user_removes_group_access(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    _attach_group(shell, tmp_path, "all")
    dev_group_path, dev_group_key = _attach_group(shell, tmp_path, "dev")
    _attach_group(shell, tmp_path, "ops")

    file = File.create(shell.current_working_directory, "report", shell.current_user)
    track_file(shell, file)

    shell.do_set_permissions("report group")
    shell.do_set_permissions("report user")

    dev_group = Group.get_group(dev_group_path, dev_group_key)
    file_id = str(file.path)

    assert file_id not in dev_group.file_access

    # Also assert no unexpected file access remains in other groups.
    for group_name, group_info in shell.current_user.group_keys.items():
        group_obj = Group.get_group(
            Path(group_info["id"]), bytes.fromhex(group_info["key"])
        )
        assert file_id not in group_obj.file_access
