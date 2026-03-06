import pytest

import main as main_module
from backend.auth import FILES_DIR
from main import SecureFS
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path):
    """Return a SecureFS with cwd inside a tmp_path that mimics FILES_DIR."""
    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = tmp_path
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cd_changes_working_directory(tmp_path, monkeypatch):
    """cd moves current_working_directory into the named subdirectory."""
    subdir = tmp_path / "docs"
    subdir.mkdir()
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = _logged_in_shell(tmp_path)
    shell.do_cd("docs")

    assert shell.current_working_directory == subdir.resolve()


def test_cd_via_arg(tmp_path, monkeypatch):
    """cd accepts the directory name directly as the arg string."""
    subdir = tmp_path / "reports"
    subdir.mkdir()
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = _logged_in_shell(tmp_path)
    shell.do_cd("reports")

    assert shell.current_working_directory == subdir.resolve()


def test_cd_no_arg(tmp_path, monkeypatch):
    """cd prompts for a name when arg is empty."""
    subdir = tmp_path / "archive"
    subdir.mkdir()
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = _logged_in_shell(tmp_path)
    shell.do_cd("")

    assert shell.current_working_directory == tmp_path / "alice"  # cd with empty arg goes to home dir


def test_cd_error_when_directory_does_not_exist(tmp_path, monkeypatch, capsys):
    """cd prints an error when the target directory does not exist."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = _logged_in_shell(tmp_path)
    shell.do_cd("nonexistent")

    captured = capsys.readouterr()
    assert "not a valid directory" in captured.out
    assert shell.current_working_directory == tmp_path


def test_cd_error_when_target_is_a_file(tmp_path, monkeypatch, capsys):
    """cd prints an error when the target path is a file, not a directory."""
    (tmp_path / "readme.txt").write_text("hello")
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = _logged_in_shell(tmp_path)
    shell.do_cd("readme.txt")

    captured = capsys.readouterr()
    assert "not a valid directory" in captured.out
    assert shell.current_working_directory == tmp_path


def test_cd_blocks_traversal_above_files_dir(tmp_path, monkeypatch, capsys):
    """cd rejects '..' paths that would escape FILES_DIR."""
    user_home = tmp_path / "alice"
    user_home.mkdir()
    # Treat the user's home dir as the files root, so '..' would escape it
    monkeypatch.setattr(main_module, "FILES_DIR", user_home)

    shell = _logged_in_shell(user_home)
    shell.do_cd("..")

    captured = capsys.readouterr()
    assert "Access outside of storage is not allowed" in captured.out
    assert shell.current_working_directory == user_home


def test_cd_blocks_absolute_path_outside_files_dir(tmp_path, monkeypatch, capsys):
    """cd rejects absolute paths that resolve outside FILES_DIR."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = _logged_in_shell(tmp_path)
    shell.do_cd("/etc")

    captured = capsys.readouterr()
    assert "Access outside of storage is not allowed" in captured.out
    assert shell.current_working_directory == tmp_path


def test_cd_does_not_change_cwd_on_error(tmp_path, monkeypatch):
    """current_working_directory is unchanged when cd fails."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    original = tmp_path

    shell = _logged_in_shell(tmp_path)
    shell.do_cd("ghost")

    assert shell.current_working_directory == original


def test_cd_allows_nested_directory(tmp_path, monkeypatch):
    """cd can navigate into a nested directory that exists."""
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = _logged_in_shell(tmp_path / "a")
    shell.do_cd("b")

    assert shell.current_working_directory == nested.resolve()
