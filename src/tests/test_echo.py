import backend.file_utils as file_utils
import main as main_module
from main import SecureFS
from models.directory import Directory
from models.file import File
from tests.encryption_helpers import load_tracked_file, track_file
from tests.path_helpers import encrypted_path
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch):
    """Return a SecureFS instance logged in with cwd inside FILES_DIR/alice."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    monkeypatch.setattr(file_utils, "add_file_to_user", lambda *args, **kwargs: True)
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


def test_echo_prints_to_stdout_without_redirect(tmp_path, monkeypatch, capsys):
    """echo without redirection prints content to stdout."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("hello world")

    captured = capsys.readouterr()
    assert captured.out == "hello world\n"


def test_echo_writes_to_file_with_overwrite_redirect(tmp_path, monkeypatch):
    """echo > writes content into the encrypted file body."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("hello > notes")

    file = load_tracked_file(
        shell, encrypted_path(shell.current_working_directory, "notes")
    )
    assert file.body == "hello\n"


def test_echo_appends_to_file_with_double_redirect(tmp_path, monkeypatch):
    """echo >> appends to existing decrypted body content."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = encrypted_path(shell.current_working_directory, "notes")

    track_file(
        shell,
        File.create(shell.current_working_directory, "notes", "alice", body="start\n"),
    )

    shell.do_echo("next >> notes")

    updated = load_tracked_file(shell, file_path)
    assert updated.body == "start\nnext\n"


def test_echo_n_flag_suppresses_newline_stdout(tmp_path, monkeypatch, capsys):
    """echo -n prints without a trailing newline when no redirection is used."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("-n hello")

    captured = capsys.readouterr()
    assert captured.out == "hello"


def test_echo_rejects_invalid_redirect_syntax(tmp_path, monkeypatch, capsys):
    """echo reports usage error when redirect has multiple target tokens."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("hello > notes extra")

    captured = capsys.readouterr()
    assert "Invalid syntax" in captured.out


def test_echo_preserves_explicit_target_name(tmp_path, monkeypatch):
    """echo preserves an explicit target name literally."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("hello > notes.backup")

    file = load_tracked_file(
        shell, encrypted_path(shell.current_working_directory, "notes.backup")
    )
    assert file.body == "hello\n"


def test_echo_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    """@requires_login prevents echo when no user is authenticated."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell = SecureFS()
    shell.current_working_directory = tmp_path

    shell.do_echo("hello")

    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out


def test_echo_reports_parse_error_for_unclosed_quote(tmp_path, monkeypatch, capsys):
    """echo reports parser errors for malformed quoted input."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo('"unterminated')

    captured = capsys.readouterr()
    assert "Error:" in captured.out


def test_echo_redirect_with_no_content_writes_newline(tmp_path, monkeypatch):
    """echo > file with empty content still writes a newline."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("> empty")

    file = load_tracked_file(
        shell, encrypted_path(shell.current_working_directory, "empty")
    )
    assert file.body == "\n"
