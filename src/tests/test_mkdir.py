from main import SecureFS
from models.directory import Directory
from tests.path_helpers import encrypted_name, encrypted_path
from tests.test_helpers import make_logged_in_shell
from tests.test_login import _make_user_data


def _logged_in_shell(tmp_path, monkeypatch):
    return make_logged_in_shell(tmp_path, monkeypatch)


def test_mkdir_creates_directory(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_mkdir("docs")
    assert encrypted_path(shell.current_working_directory, "docs").is_dir()
    assert "created" in capsys.readouterr().out


def test_mkdir_error_when_directory_already_exists(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    encrypted_path(shell.current_working_directory, "photos").mkdir(parents=True)
    shell.do_mkdir("photos")
    out = capsys.readouterr().out
    assert "already exists" in out
    assert "created" not in out


def test_mkdir_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    import main as main_module

    shell = SecureFS()
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell.current_working_directory = tmp_path
    shell.do_mkdir("docs")
    assert "Must be logged in" in capsys.readouterr().out


def test_mkdir_aborts_when_name_is_empty(tmp_path, monkeypatch, capsys):
    import main as main_module

    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: None)
    shell.do_mkdir("")
    assert list(shell.current_working_directory.iterdir()) == []


def test_mkdir_multiple_distinct_directories(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    for name in ("alpha", "beta", "gamma"):
        shell.do_mkdir(name)
    dirs = {p.name for p in shell.current_working_directory.iterdir() if p.is_dir()}
    assert dirs == {
        encrypted_name("alpha"),
        encrypted_name("beta"),
        encrypted_name("gamma"),
    }


def test_mkdir_blocked_outside_home_directory(tmp_path, monkeypatch, capsys):
    import main as main_module

    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    other_user = encrypted_path(tmp_path, "bob")
    other_user.mkdir()
    shell = SecureFS()
    shell.current_user = _make_user_data(username="alice")
    shell.current_working_directory = other_user
    shell.do_mkdir("secret")
    assert (
        "Cannot create directories outside of your home directory"
        in capsys.readouterr().out
    )


def test_mkdir_allowed_in_subdirectory_of_home(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = Directory.create(
        shell.current_working_directory, "documents", shell.current_user
    )
    shell.current_working_directory = subdir.path
    shell.do_mkdir("nested")
    assert "created" in capsys.readouterr().out
    assert encrypted_path(subdir.path, "nested").is_dir()
