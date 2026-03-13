import main as main_module
from main import SecureFS
from models.file import File
from tests.encryption_helpers import track_file
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


def test_mv_renames_file_in_current_directory(tmp_path, monkeypatch):
    """mv renames a file within the current directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "old", "alice"))

    shell.do_mv("old new")

    assert not (tmp_path / "alice" / "old").exists()
    assert (tmp_path / "alice" / "new").exists()


def test_mv_errors_when_source_missing(tmp_path, monkeypatch, capsys):
    """mv prints an error when source does not exist."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_mv("ghost new")

    captured = capsys.readouterr()
    assert "Source file 'ghost' does not exist" in captured.out


def test_mv_errors_when_destination_exists(tmp_path, monkeypatch, capsys):
    """mv prints an error when destination already exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "old", "alice"))
    track_file(shell, File.create(tmp_path / "alice", "new", "alice"))

    shell.do_mv("old new")

    captured = capsys.readouterr()
    assert "Destination file 'new' already exists" in captured.out


def test_mv_rejects_invalid_syntax(tmp_path, monkeypatch, capsys):
    """mv prints usage error when required arguments are missing."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_mv("only_source")

    captured = capsys.readouterr()
    assert "Invalid syntax" in captured.out


def test_mv_supports_quoted_names_with_spaces(tmp_path, monkeypatch):
    """mv supports quoted source/destination names containing spaces."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "old name", "alice"))

    shell.do_mv('"old name" "new name"')

    assert not (tmp_path / "alice" / "old name").exists()
    assert (tmp_path / "alice" / "new name").exists()


def test_mv_with_json_suffix_argument_is_not_supported(tmp_path, monkeypatch, capsys):
    """mv treats a .json suffix literally when looking up the source path."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "old", "alice"))

    shell.do_mv("old.json new")

    captured = capsys.readouterr()
    assert "Source file 'old.json' does not exist" in captured.out


def test_mv_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    """@requires_login prevents mv when no user is authenticated."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell = SecureFS()
    shell.current_working_directory = tmp_path

    shell.do_mv("old new")

    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out


def test_mv_invalid_syntax_does_not_change_existing_files(
    tmp_path, monkeypatch, capsys
):
    """mv with invalid syntax should not alter files in cwd."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "old", "alice"))
    original = sorted(p.name for p in (tmp_path / "alice").iterdir())

    shell.do_mv("old")

    captured = capsys.readouterr()
    assert "Invalid syntax" in captured.out
    after = sorted(p.name for p in (tmp_path / "alice").iterdir())
    assert after == original
