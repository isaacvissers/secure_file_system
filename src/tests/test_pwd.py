from models.directory import Directory
from tests.test_helpers import make_logged_in_shell


def _logged_in_shell(tmp_path, monkeypatch):
    return make_logged_in_shell(tmp_path, monkeypatch)


def test_pwd_prints_current_home_directory(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_pwd("")
    assert capsys.readouterr().out.strip() == "SFS/alice"


def test_pwd_prints_nested_directory(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    nested = Directory.create(
        shell.current_working_directory, "docs", shell.current_user
    )
    shell.current_working_directory = nested.path
    shell.do_pwd("")
    assert capsys.readouterr().out.strip() == "SFS/alice/docs"


def test_pwd_blocked_when_not_logged_in(capsys):
    from main import SecureFS

    shell = SecureFS()
    shell.do_pwd("")
    assert "Must be logged in" in capsys.readouterr().out


def test_pwd_prints_sfs_when_cwd_outside_files_dir(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.current_working_directory = tmp_path.parent
    shell.do_pwd("")
    assert capsys.readouterr().out.strip() == "SFS"


def test_pwd_ignores_extra_arguments(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_pwd("unexpected tokens")
    assert capsys.readouterr().out.strip() == "SFS/alice"
