from main import SecureFS
from models.file import File
from tests.encryption_helpers import load_tracked_file, track_file
from tests.path_helpers import encrypted_path
from tests.test_helpers import make_logged_in_shell


def _logged_in_shell(tmp_path, monkeypatch):
    return make_logged_in_shell(tmp_path, monkeypatch)


def test_echo_prints_to_stdout_without_redirect(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_echo("hello world")
    assert capsys.readouterr().out == "hello world\n"


def test_echo_writes_to_file_with_overwrite_redirect(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_echo("hello > notes")
    file = load_tracked_file(
        shell, encrypted_path(shell.current_working_directory, "notes")
    )
    assert file.body == "hello\n"


def test_echo_appends_to_file_with_double_redirect(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = encrypted_path(shell.current_working_directory, "notes")
    track_file(
        shell,
        File.create(
            shell.current_working_directory, "notes", shell.current_user, body="start\n"
        ),
    )
    shell.do_echo("next >> notes")
    assert load_tracked_file(shell, file_path).body == "start\nnext\n"


def test_echo_n_flag_suppresses_newline_stdout(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_echo("-n hello")
    assert capsys.readouterr().out == "hello"


def test_echo_rejects_invalid_redirect_syntax(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_echo("hello > notes extra")
    assert "Invalid syntax" in capsys.readouterr().out


def test_echo_preserves_explicit_target_name(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_echo("hello > notes.backup")
    file = load_tracked_file(
        shell, encrypted_path(shell.current_working_directory, "notes.backup")
    )
    assert file.body == "hello\n"


def test_echo_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    import main as main_module

    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell = SecureFS()
    shell.current_working_directory = tmp_path
    shell.do_echo("hello")
    assert "Must be logged in" in capsys.readouterr().out
