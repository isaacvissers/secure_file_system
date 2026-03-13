import pytest

import main as main_module
from main import SecureFS
from models.directory import Directory
from models.file import File
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch):
    """Return a SecureFS with cwd inside a tmp_path that mimics FILES_DIR."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    user_home = Directory.create(tmp_path, "alice", "alice")
    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_user["file_keys"][
        str(user_home.metadata.path)
    ] = user_home.metadata.encrypted_file_key.hex()
    shell.current_working_directory = user_home.path
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cd_changes_working_directory(tmp_path, monkeypatch):
    """cd moves current_working_directory into the named subdirectory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = Directory.create(shell.current_working_directory, "docs", "alice")

    shell.do_cd("docs")

    assert shell.current_working_directory == subdir.path.resolve()


def test_cd_via_arg(tmp_path, monkeypatch):
    """cd accepts the directory name directly as the arg string."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = Directory.create(shell.current_working_directory, "reports", "alice")

    shell.do_cd("reports")

    assert shell.current_working_directory == subdir.path.resolve()


def test_cd_no_arg(tmp_path, monkeypatch):
    """cd prompts for a name when arg is empty."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    expected_home = shell.current_working_directory
    shell.do_cd("")

    assert shell.current_working_directory == expected_home


def test_cd_error_when_directory_does_not_exist(tmp_path, monkeypatch, capsys):
    """cd prints an error when the target directory does not exist."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    original = shell.current_working_directory
    shell.do_cd("nonexistent")

    captured = capsys.readouterr()
    assert "not a valid directory" in captured.out
    assert shell.current_working_directory == original


def test_cd_error_when_target_is_a_file(tmp_path, monkeypatch, capsys):
    """cd prints an error when the target path is a file, not a directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    File.create(shell.current_working_directory, "readme.txt", "alice")
    original = shell.current_working_directory
    shell.do_cd("readme.txt")

    captured = capsys.readouterr()
    assert "not a valid directory" in captured.out
    assert shell.current_working_directory == original


def test_cd_blocks_traversal_above_files_dir(tmp_path, monkeypatch, capsys):
    """cd treats '..' literally and rejects missing hashed directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    original = shell.current_working_directory
    shell.do_cd("..")

    captured = capsys.readouterr()
    assert "not a valid directory" in captured.out
    assert shell.current_working_directory == original


def test_cd_blocks_absolute_path_outside_files_dir(tmp_path, monkeypatch, capsys):
    """cd treats absolute-looking arg literally and rejects missing hashed directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    original = shell.current_working_directory
    shell.do_cd("/etc")

    captured = capsys.readouterr()
    assert "not a valid directory" in captured.out
    assert shell.current_working_directory == original


def test_cd_does_not_change_cwd_on_error(tmp_path, monkeypatch):
    """current_working_directory is unchanged when cd fails."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    original = shell.current_working_directory
    shell.do_cd("ghost")

    assert shell.current_working_directory == original


def test_cd_allows_nested_directory(tmp_path, monkeypatch):
    """cd can navigate into a nested directory that exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    a = Directory.create(shell.current_working_directory, "a", "alice")
    b = Directory.create(a.path, "b", "alice")
    shell.current_working_directory = a.path
    shell.do_cd("b")

    assert shell.current_working_directory == b.path.resolve()
