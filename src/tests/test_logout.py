from main import SecureFS
from tests.test_helpers import make_logged_in_shell


def _logged_in_shell(tmp_path, monkeypatch):
    return make_logged_in_shell(tmp_path, monkeypatch)


def test_logout_clears_current_user(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_logout("")
    assert shell.current_user is None


def test_logout_clears_working_directory(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_logout("")
    assert shell.current_working_directory is None


def test_logout_resets_prompt(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    assert shell.prompt == "SFS/alice> "
    shell.do_logout("")
    assert shell.prompt == "SFS> "


def test_logout_prints_success_message(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_logout("")
    assert "Log Out successful" in capsys.readouterr().out


def test_logout_rejected_when_not_logged_in(capsys):
    shell = SecureFS()
    shell.do_logout("")
    out = capsys.readouterr().out
    assert "Must be logged in" in out
    assert "Log Out successful" not in out


def test_logout_idempotent_prompt_reset(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_logout("")
    shell._update_prompt()
    assert shell.prompt == "SFS> "
