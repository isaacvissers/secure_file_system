from models.directory import Directory
from models.file import File
from tests.encryption_helpers import track_file
from tests.test_helpers import make_logged_in_shell


def _logged_in_shell(tmp_path, monkeypatch):
    return make_logged_in_shell(tmp_path, monkeypatch)


def test_ls_empty_directory(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    shell.do_ls("")
    assert capsys.readouterr().out == ""


def test_ls_shows_directory_with_trailing_slash(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    docs = Directory.create(shell.current_working_directory, "docs", shell.current_user)
    track_file(shell, docs.metadata)
    shell.do_ls("")
    assert "docs/" in capsys.readouterr().out


def test_ls_shows_plain_file_name(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(
        shell, File.create(shell.current_working_directory, "notes", shell.current_user)
    )
    shell.do_ls("")
    assert "notes" in capsys.readouterr().out


def test_ls_hides_directory_metadata_file_when_matching_directory_exists(
    tmp_path, monkeypatch, capsys
):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    docs = Directory.create(shell.current_working_directory, "docs", shell.current_user)
    track_file(shell, docs.metadata)
    shell.do_ls("")
    out = capsys.readouterr().out
    assert "docs/" in out
    assert docs.metadata.path.name not in out


def test_ls_mixed_entries(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    images = Directory.create(
        shell.current_working_directory, "images", shell.current_user
    )
    track_file(shell, images.metadata)
    track_file(
        shell,
        File.create(shell.current_working_directory, "readme", shell.current_user),
    )
    shell.do_ls("")
    lines = capsys.readouterr().out.splitlines()
    assert "images/" in lines
    assert "readme" in lines


def test_ls_works_in_subdirectory(tmp_path, monkeypatch, capsys):
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = Directory.create(
        shell.current_working_directory, "projects", shell.current_user
    )
    track_file(shell, subdir.metadata)
    track_file(shell, File.create(subdir.path, "plan", shell.current_user))
    shell.current_working_directory = subdir.path
    shell.do_ls("")
    assert "plan" in capsys.readouterr().out
