from main import SecureFS
from models.directory import Directory
from tests.path_helpers import encrypted_path
from tests.test_helpers import make_logged_in_shell
from tests.test_login import _make_user_data


def _logged_in_shell(tmp_path, monkeypatch):
    return make_logged_in_shell(tmp_path, monkeypatch)


def test_touch_creates_file(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_touch("notes")
    assert encrypted_path(shell.current_working_directory, "notes").exists()
    assert "created" in capsys.readouterr().out


def test_touch_prints_success_message(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_touch("report")
    out = capsys.readouterr().out
    assert "report" in out
    assert "created" in out


def test_touch_error_when_file_already_exists(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    encrypted_path(shell.current_working_directory, "dup").write_text("{}")
    shell.do_touch("dup")
    out = capsys.readouterr().out
    assert "Error" in out
    assert "created" not in out


def test_touch_aborts_when_name_is_empty(tmp_path, monkeypatch, capsys):
    import main as main_module

    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: None)
    shell.do_touch("")
    assert list(shell.current_working_directory.iterdir()) == []


def test_touch_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    import main as main_module

    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell = SecureFS()
    shell.current_working_directory = tmp_path
    shell.do_touch("secret")
    assert "Must be logged in" in capsys.readouterr().out


def test_touch_blocked_outside_home_directory(tmp_path, monkeypatch, capsys):
    import main as main_module

    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    other_user = encrypted_path(tmp_path, "bob")
    other_user.mkdir()
    shell = SecureFS()
    shell.current_user = _make_user_data(username="alice")
    shell.current_working_directory = other_user
    shell.do_touch("stolen")
    assert (
        "Cannot create files outside of your home directory" in capsys.readouterr().out
    )


def test_touch_allowed_in_subdirectory_of_home(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = Directory.create(
        shell.current_working_directory, "documents", shell.current_user
    )
    shell.current_working_directory = subdir.path
    shell.do_touch("nested")
    assert "created" in capsys.readouterr().out
    assert encrypted_path(subdir.path, "nested").exists()
