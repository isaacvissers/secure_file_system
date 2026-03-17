import hashlib

import main as main_module
from main import SecureFS
from models.directory import Directory
from models.file import File
from tests.test_helpers import make_logged_in_shell


def _logged_in_shell(tmp_path, monkeypatch):
    return make_logged_in_shell(tmp_path, monkeypatch)


def test_cd_changes_working_directory(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = Directory.create(
        shell.current_working_directory, "docs", shell.current_user
    )
    shell.do_cd("docs")
    assert shell.current_working_directory == subdir.path.resolve()


def test_cd_no_arg_returns_home(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = Directory.create(
        shell.current_working_directory, "reports", shell.current_user
    )
    shell.current_working_directory = subdir.path
    shell.do_cd("")
    assert shell.current_working_directory == (
        tmp_path / hashlib.sha256(b"alice").hexdigest()
    )


def test_cd_error_when_directory_does_not_exist(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    original = shell.current_working_directory
    shell.do_cd("nonexistent")
    assert "not a valid directory" in capsys.readouterr().out
    assert shell.current_working_directory == original


def test_cd_error_when_target_is_a_file(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    File.create(shell.current_working_directory, "readme.txt", shell.current_user)
    original = shell.current_working_directory
    shell.do_cd("readme.txt")
    assert "not a valid directory" in capsys.readouterr().out
    assert shell.current_working_directory == original


def test_cd_blocks_traversal_above_files_dir(tmp_path, monkeypatch, capsys):
    helper_shell = _logged_in_shell(tmp_path, monkeypatch)
    shell = SecureFS()
    shell.current_user = helper_shell.current_user
    shell.current_user_key = None
    shell.current_working_directory = tmp_path
    shell.do_cd("..")
    assert "Access outside of storage is not allowed" in capsys.readouterr().out


def test_cd_blocks_absolute_path_outside_files_dir(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    original = shell.current_working_directory
    shell.do_cd("/etc")
    assert "not a valid directory" in capsys.readouterr().out
    assert shell.current_working_directory == original


def test_cd_allows_nested_directory(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    first = Directory.create(shell.current_working_directory, "a", shell.current_user)
    second = Directory.create(first.path, "b", shell.current_user)
    shell.current_working_directory = first.path
    shell.do_cd("b")
    assert shell.current_working_directory == second.path.resolve()
