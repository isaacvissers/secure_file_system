import main as main_module
from main import SecureFS
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path):
    """Return a SecureFS instance logged in with cwd pointing at tmp_path."""
    shell = SecureFS()
    shell.current_user = {
        "user_data": _make_user_data(user_id=1, username="alice"),
        "private_key": object(),
    }
    shell.current_working_directory = tmp_path
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_mkdir_creates_directory(tmp_path, monkeypatch, capsys):
    """mkdir creates the requested directory inside current_working_directory."""
    shell = _logged_in_shell(tmp_path)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "docs")

    shell.do_mkdir("")

    assert (tmp_path / "docs").is_dir()
    captured = capsys.readouterr()
    assert "created" in captured.out


def test_mkdir_prints_success_message(tmp_path, monkeypatch, capsys):
    """mkdir prints a confirmation containing the directory name."""
    shell = _logged_in_shell(tmp_path)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "reports")

    shell.do_mkdir("")

    captured = capsys.readouterr()
    assert "reports" in captured.out
    assert "created" in captured.out


def test_mkdir_error_when_directory_already_exists(tmp_path, monkeypatch, capsys):
    """mkdir prints an error and does not raise when the directory already exists."""
    existing = tmp_path / "photos"
    existing.mkdir()

    shell = _logged_in_shell(tmp_path)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "photos")

    shell.do_mkdir("")

    captured = capsys.readouterr()
    assert "already exists" in captured.out
    assert "created" not in captured.out


def test_mkdir_does_not_overwrite_existing_directory(tmp_path, monkeypatch, capsys):
    """An existing directory is left untouched when mkdir is blocked."""
    existing = tmp_path / "vault"
    existing.mkdir()
    sentinel = existing / "sentinel.txt"
    sentinel.write_text("keep me")

    shell = _logged_in_shell(tmp_path)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "vault")

    shell.do_mkdir("")

    assert sentinel.exists()


def test_mkdir_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    """@requires_login prevents mkdir when no user is authenticated."""
    shell = SecureFS()
    shell.current_working_directory = tmp_path

    shell.do_mkdir("")

    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out
    # No directory should have been created
    assert list(tmp_path.iterdir()) == []


def test_mkdir_aborts_when_name_is_empty(tmp_path, monkeypatch, capsys):
    """mkdir returns early (no directory created) when prompt_required_text returns None."""
    shell = _logged_in_shell(tmp_path)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: None)

    shell.do_mkdir("")

    assert list(tmp_path.iterdir()) == []


def test_mkdir_creates_directory_in_cwd(tmp_path, monkeypatch):
    """The new directory is a direct child of current_working_directory."""
    shell = _logged_in_shell(tmp_path)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "archive")

    shell.do_mkdir("")

    expected = tmp_path / "archive"
    assert expected.exists() and expected.is_dir()


def test_mkdir_multiple_distinct_directories(tmp_path, monkeypatch, capsys):
    """Each mkdir call for a unique name succeeds independently."""
    shell = _logged_in_shell(tmp_path)
    for name in ("alpha", "beta", "gamma"):
        monkeypatch.setattr(
            main_module, "prompt_required_text", lambda label, n=name: n
        )
        shell.do_mkdir("")

    dirs = {p.name for p in tmp_path.iterdir() if p.is_dir()}
    assert dirs == {"alpha", "beta", "gamma"}
