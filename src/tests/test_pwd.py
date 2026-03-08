import main as main_module
from main import SecureFS
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch):
    """Return a SecureFS instance logged in with cwd inside FILES_DIR/alice."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    user_home = tmp_path / "alice"
    user_home.mkdir(exist_ok=True)

    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = user_home
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_pwd_prints_current_home_directory(tmp_path, monkeypatch, capsys):
    """pwd prints the current directory relative to FILES_DIR."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_pwd("")

    captured = capsys.readouterr()
    assert "SFS/alice" in captured.out


def test_pwd_prints_nested_directory(tmp_path, monkeypatch, capsys):
    """pwd reflects nested directories under the current user's home."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    nested = tmp_path / "alice" / "docs"
    nested.mkdir()
    shell.current_working_directory = nested

    shell.do_pwd("")

    captured = capsys.readouterr()
    assert "SFS/alice/docs" in captured.out


def test_pwd_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    """@requires_login prevents pwd when no user is authenticated."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell = SecureFS()
    shell.current_working_directory = tmp_path

    shell.do_pwd("")

    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out


def test_pwd_prints_sfs_when_cwd_outside_files_dir(tmp_path, monkeypatch, capsys):
    """pwd falls back to plain SFS when cwd is outside FILES_DIR."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    outside = tmp_path.parent
    shell.current_working_directory = outside

    shell.do_pwd("")

    captured = capsys.readouterr()
    assert captured.out.strip() == "SFS"


def test_pwd_ignores_extra_arguments(tmp_path, monkeypatch, capsys):
    """pwd ignores extra args and still prints current directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_pwd("unexpected tokens")

    captured = capsys.readouterr()
    assert "SFS/alice" in captured.out
