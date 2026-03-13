import main as main_module
from main import SecureFS
from models.directory import Directory
from models.file import File
from tests.encryption_helpers import track_file
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch):
    """Return a SecureFS instance with cwd set to FILES_DIR/alice."""
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


def test_ls_empty_directory(tmp_path, monkeypatch, capsys):
    """ls prints nothing when the directory is empty."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_ls("")

    captured = capsys.readouterr()
    assert captured.out == ""


def test_ls_shows_directory_with_trailing_slash(tmp_path, monkeypatch, capsys):
    """ls prints directories with a trailing '/'."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    docs = Directory.create(shell.current_working_directory, "docs", "alice")
    track_file(shell, docs.metadata)

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "docs/" in captured.out


def test_ls_shows_plain_file_name(tmp_path, monkeypatch, capsys):
    """ls prints plain file names as-is."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "notes", "alice"))

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "notes" in captured.out


def test_ls_hides_directory_metadata_file_when_matching_directory_exists(
    tmp_path, monkeypatch, capsys
):
    """ls hides a dotfile metadata entry when a matching directory exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    docs = Directory.create(shell.current_working_directory, "docs", "alice")
    track_file(shell, docs.metadata)

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "docs/" in captured.out
    assert "displaying encrypted name" not in captured.out


def test_ls_shows_plain_file_without_matching_directory(tmp_path, monkeypatch, capsys):
    """ls shows a regular file when no matching directory exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "report", "alice"))

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "report" in captured.out


def test_ls_mixed_entries(tmp_path, monkeypatch, capsys):
    """ls correctly handles a mix of directories and files."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    images = Directory.create(shell.current_working_directory, "images", "alice")
    track_file(shell, images.metadata)
    track_file(shell, File.create(shell.current_working_directory, "readme", "alice"))

    shell.do_ls("")

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert "images/" in lines
    assert "readme" in lines
    assert "displaying encrypted name" not in captured.out


def test_ls_multiple_files(tmp_path, monkeypatch, capsys):
    """ls lists all plain files when no matching directories exist."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    for name in ("alpha", "beta", "gamma"):
        track_file(shell, File.create(shell.current_working_directory, name, "alice"))

    shell.do_ls("")

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert "alpha" in lines
    assert "beta" in lines
    assert "gamma" in lines


def test_ls_multiple_directories(tmp_path, monkeypatch, capsys):
    """ls lists all subdirectories with trailing slashes."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    for name in ("music", "videos", "photos"):
        directory = Directory.create(shell.current_working_directory, name, "alice")
        track_file(shell, directory.metadata)

    shell.do_ls("")

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert "music/" in lines
    assert "videos/" in lines
    assert "photos/" in lines


def test_ls_works_in_subdirectory(tmp_path, monkeypatch, capsys):
    """ls works correctly when cwd is a subdirectory of the user home."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = Directory.create(shell.current_working_directory, "projects", "alice")
    track_file(shell, subdir.metadata)
    track_file(shell, File.create(subdir.path, "plan", "alice"))
    shell.current_working_directory = subdir.path

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "plan" in captured.out
