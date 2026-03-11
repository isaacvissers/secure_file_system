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


def test_cat_reads_file_body(tmp_path, monkeypatch, capsys):
    """cat prints the decrypted file body for a valid encrypted file."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "notes", body="hello world"))

    shell.do_cat("notes")

    captured = capsys.readouterr()
    assert "hello world" in captured.out


def test_cat_requires_file_name(tmp_path, monkeypatch, capsys):
    """cat prints an error when no filename is provided."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_cat("")

    captured = capsys.readouterr()
    assert "File name is required" in captured.out


def test_cat_errors_for_missing_file(tmp_path, monkeypatch, capsys):
    """cat prints an error when the target file does not exist."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_cat("ghost")

    captured = capsys.readouterr()
    assert "not a valid file" in captured.out


def test_cat_errors_when_file_key_is_missing(tmp_path, monkeypatch, capsys):
    """cat reports a read error when the session does not have the file key."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    File.create(tmp_path / "alice", "broken", body="secret")

    shell.do_cat("broken")

    captured = capsys.readouterr()
    assert "Error reading file" in captured.out


def test_cat_with_json_suffix_argument_is_not_supported(tmp_path, monkeypatch, capsys):
    """cat currently appends .json, so passing .json in arg should fail lookup."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "notes"))

    shell.do_cat("notes.json")

    captured = capsys.readouterr()
    assert "not a valid file" in captured.out


def test_cat_handles_malformed_json_file(tmp_path, monkeypatch, capsys):
    """cat reports read errors when target file is not a valid encrypted payload."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    broken_file = tmp_path / "alice" / "broken.json"
    broken_file.write_text("{not-json", encoding="utf-8")

    shell.do_cat("broken")

    captured = capsys.readouterr()
    assert "Error reading file" in captured.out


def test_cat_prints_blank_line_for_empty_body(tmp_path, monkeypatch, capsys):
    """cat prints a newline when the decrypted body is empty."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "empty"))

    shell.do_cat("empty")

    captured = capsys.readouterr()
    assert captured.out == "\n"
