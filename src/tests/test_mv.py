from main import SecureFS
from models.file import File
from tests.encryption_helpers import track_file
from tests.path_helpers import encrypted_path
from tests.test_helpers import make_logged_in_shell


def _logged_in_shell(tmp_path, monkeypatch):
    return make_logged_in_shell(tmp_path, monkeypatch)


def test_mv_renames_file_in_current_directory(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(
        shell, File.create(shell.current_working_directory, "old", shell.current_user)
    )
    shell.do_mv("old new")
    assert not encrypted_path(shell.current_working_directory, "old").exists()
    assert encrypted_path(shell.current_working_directory, "new").exists()


def test_mv_errors_when_source_missing(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_mv("ghost new")
    assert "Source file 'ghost' does not exist" in capsys.readouterr().out


def test_mv_errors_when_destination_exists(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(
        shell, File.create(shell.current_working_directory, "old", shell.current_user)
    )
    track_file(
        shell, File.create(shell.current_working_directory, "new", shell.current_user)
    )
    shell.do_mv("old new")
    assert "Destination file 'new' already exists" in capsys.readouterr().out


def test_mv_rejects_invalid_syntax(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_mv("only_source")
    assert "Invalid syntax" in capsys.readouterr().out


def test_mv_supports_quoted_names_with_spaces(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(
        shell,
        File.create(shell.current_working_directory, "old name", shell.current_user),
    )
    shell.do_mv('"old name" "new name"')
    assert not encrypted_path(shell.current_working_directory, "old name").exists()
    assert encrypted_path(shell.current_working_directory, "new name").exists()


def test_mv_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    import main as main_module

    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell = SecureFS()
    shell.current_working_directory = tmp_path
    shell.do_mv("old new")
    assert "Must be logged in" in capsys.readouterr().out


def test_mv_updates_persisted_file_info_for_renamed_file(tmp_path, monkeypatch):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    File.create(shell.current_working_directory, "old", shell.current_user)
    old_path = encrypted_path(shell.current_working_directory, "old")
    new_path = encrypted_path(shell.current_working_directory, "new")
    assert str(old_path) in shell.current_user.file_info
    shell.do_mv("old new")
    assert str(old_path) not in shell.current_user.file_info
    assert str(old_path) not in shell.current_user.file_keys
    assert shell.current_user.file_info[str(new_path)] == "new"
