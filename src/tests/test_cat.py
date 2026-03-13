import main as main_module
from main import SecureFS
from models.directory import Directory
from models.file import File
from tests.encryption_helpers import track_file
from tests.path_helpers import encrypted_path
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch):
    """Return a SecureFS instance logged in with cwd inside FILES_DIR/alice."""
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


def test_cat_reads_file_body(tmp_path, monkeypatch, capsys):
    """cat prints the decrypted file body for a valid encrypted file."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(
        shell,
        File.create(
            shell.current_working_directory, "notes", "alice", body="hello world"
        ),
    )

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
    File.create(shell.current_working_directory, "broken", "alice", body="secret")

    shell.do_cat("broken")

    captured = capsys.readouterr()
    assert "Error reading file" in captured.out


def test_cat_with_json_suffix_argument_is_not_supported(tmp_path, monkeypatch, capsys):
    """cat treats a .json suffix literally when looking up the path."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "notes", "alice"))

    shell.do_cat("notes.json")

    captured = capsys.readouterr()
    assert "not a valid file" in captured.out


def test_cat_handles_malformed_json_file(tmp_path, monkeypatch, capsys):
    """cat reports read errors when target file is not a valid encrypted payload."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    broken_file = encrypted_path(shell.current_working_directory, "broken")
    broken_file.write_text("{not-json", encoding="utf-8")

    shell.do_cat("broken")

    captured = capsys.readouterr()
    assert "Error reading file" in captured.out


def test_cat_prints_blank_line_for_empty_body(tmp_path, monkeypatch, capsys):
    """cat prints a newline when the decrypted body is empty."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "empty", "alice"))
    capsys.readouterr()

    shell.do_cat("empty")

    captured = capsys.readouterr()
    assert captured.out == "\n"
