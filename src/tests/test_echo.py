import json

import main as main_module
from main import SecureFS
from models.file import File
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


def test_echo_prints_to_stdout_without_redirect(tmp_path, monkeypatch, capsys):
    """echo without redirection prints content to stdout."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("hello world")

    captured = capsys.readouterr()
    assert captured.out == "hello world\n"


def test_echo_writes_to_file_with_overwrite_redirect(tmp_path, monkeypatch):
    """echo > writes content into the file's encrypted_body field."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("hello > notes")

    data = json.loads((tmp_path / "alice" / "notes.json").read_text(encoding="utf-8"))
    assert data["encrypted_body"] == "hello\n"


def test_echo_appends_to_file_with_double_redirect(tmp_path, monkeypatch):
    """echo >> appends to existing encrypted_body content."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = tmp_path / "alice" / "notes.json"

    File.create(tmp_path / "alice", "notes")
    data = json.loads(file_path.read_text(encoding="utf-8"))
    data["encrypted_body"] = "start\n"
    file_path.write_text(json.dumps(data, indent=4), encoding="utf-8")

    shell.do_echo("next >> notes")

    updated = json.loads(file_path.read_text(encoding="utf-8"))
    assert updated["encrypted_body"] == "start\nnext\n"


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


def test_echo_accepts_explicit_json_target_name(tmp_path, monkeypatch):
    """echo keeps an explicit .json target name without duplicating suffix."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_echo("hello > notes.json")

    data = json.loads((tmp_path / "alice" / "notes.json").read_text(encoding="utf-8"))
    assert data["encrypted_body"] == "hello\n"


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

    data = json.loads((tmp_path / "alice" / "empty.json").read_text(encoding="utf-8"))
    assert data["encrypted_body"] == "\n"
