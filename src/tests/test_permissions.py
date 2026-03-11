import main as main_module
from main import SecureFS
from models.directory import Directory
from models.file import File
from tests.encryption_helpers import load_tracked_file, track_file
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch, username="alice"):
    """Return a SecureFS instance logged in with cwd inside FILES_DIR/<username>."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    user_home = tmp_path / username
    user_home.mkdir(exist_ok=True)
    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username=username)
    shell.current_working_directory = user_home
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# set_permissions tests
# ---------------------------------------------------------------------------


def test_set_permissions_to_user(tmp_path, monkeypatch, capsys):
    """set_permissions successfully sets permission to 'user'."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = tmp_path / "alice" / "test.json"
    track_file(shell, File.create(tmp_path / "alice", "test", "alice"))

    shell.do_set_permissions("test user")

    assert load_tracked_file(shell, file_path).permission.value == "user"


def test_set_permissions_to_group(tmp_path, monkeypatch, capsys):
    """set_permissions successfully sets permission to 'group'."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = tmp_path / "alice" / "test.json"
    track_file(shell, File.create(tmp_path / "alice", "test", "alice"))

    shell.do_set_permissions("test group")

    assert load_tracked_file(shell, file_path).permission.value == "group"


def test_set_permissions_to_all(tmp_path, monkeypatch, capsys):
    """set_permissions successfully sets permission to 'all'."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = tmp_path / "alice" / "test.json"
    track_file(shell, File.create(tmp_path / "alice", "test", "alice"))

    shell.do_set_permissions("test all")

    assert load_tracked_file(shell, file_path).permission.value == "all"


def test_set_permissions_file_not_found(tmp_path, monkeypatch, capsys):
    """set_permissions shows error when file doesn't exist."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_set_permissions("nonexistent user")

    captured = capsys.readouterr()
    assert "does not exist" in captured.out


def test_set_permissions_invalid_permission_value(tmp_path, monkeypatch, capsys):
    """set_permissions shows error for invalid permission value."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "test", "alice"))

    shell.do_set_permissions("test invalid")

    captured = capsys.readouterr()
    assert "Invalid permissions format" in captured.out
    assert "user" in captured.out
    assert "group" in captured.out
    assert "all" in captured.out


def test_set_permissions_wrong_number_of_args(tmp_path, monkeypatch, capsys):
    """set_permissions shows error when wrong number of arguments provided."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_set_permissions("test")

    captured = capsys.readouterr()
    assert "Invalid syntax" in captured.out


def test_set_permissions_no_args(tmp_path, monkeypatch, capsys):
    """set_permissions shows error when no arguments provided."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_set_permissions("")

    captured = capsys.readouterr()
    assert "Invalid syntax" in captured.out


def test_set_permissions_not_owner(tmp_path, monkeypatch, capsys):
    """set_permissions shows error when trying to modify file outside user's directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch, username="alice")
    # Create a file in bob's directory
    bob_home = tmp_path / "bob"
    bob_home.mkdir(exist_ok=True)
    File.create(bob_home, "test", "bob")

    # Try to set permissions from alice's directory
    shell.current_working_directory = bob_home

    shell.do_set_permissions("test user")

    captured = capsys.readouterr()
    assert "not the owner" in captured.out


def test_set_permissions_strips_trailing_slash(tmp_path, monkeypatch, capsys):
    """set_permissions strips trailing slash from file name."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    file_path = tmp_path / "alice" / "test.json"
    track_file(shell, File.create(tmp_path / "alice", "test", "alice"))

    shell.do_set_permissions("test/ user")

    assert load_tracked_file(shell, file_path).permission.value == "user"


def test_set_permissions_recursive_updates_subtree(tmp_path, monkeypatch, capsys):
    """set_permissions with -r updates nested directory and file metadata."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    home = tmp_path / "alice"

    project = Directory.create(home, "project", "alice")
    track_file(shell, project.metadata)
    readme = File.create(home / "project", "readme", "alice")
    track_file(shell, readme)
    docs = Directory.create(home / "project", "docs", "alice")
    track_file(shell, docs.metadata)
    notes = File.create(home / "project" / "docs", "notes", "alice")
    track_file(shell, notes)

    shell.do_set_permissions("project all -r")

    for path in [
        home / "project.json",
        home / "project" / "readme.json",
        home / "project" / "docs.json",
        home / "project" / "docs" / "notes.json",
    ]:
        assert load_tracked_file(shell, path).permission.value == "all"


def test_set_permissions_without_recursive_keeps_children(
    tmp_path, monkeypatch, capsys
):
    """set_permissions without -r only updates target metadata file."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    home = tmp_path / "alice"

    project = Directory.create(home, "project", "alice")
    track_file(shell, project.metadata)
    readme = File.create(home / "project", "readme", "alice")
    track_file(shell, readme)

    shell.do_set_permissions("project group")

    assert load_tracked_file(shell, home / "project.json").permission.value == "group"
    assert (
        load_tracked_file(shell, home / "project" / "readme.json").permission.value
        == "user"
    )


def test_set_permissions_invalid_third_argument(tmp_path, monkeypatch, capsys):
    """set_permissions rejects third args other than -r."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "test", "alice"))

    shell.do_set_permissions("test user -x")

    captured = capsys.readouterr()
    assert "Invalid syntax" in captured.out


# ---------------------------------------------------------------------------
# get_permissions tests
# ---------------------------------------------------------------------------


def test_get_permissions_returns_user(tmp_path, monkeypatch, capsys):
    """get_permissions returns the permission value for a file."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "test", "alice"))

    shell.do_get_permissions("test")

    captured = capsys.readouterr()
    assert "user" in captured.out


def test_get_permissions_after_set(tmp_path, monkeypatch, capsys):
    """get_permissions returns updated permission after set_permissions."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "test", "alice"))

    shell.do_set_permissions("test group")
    capsys.readouterr()  # Clear output

    shell.do_get_permissions("test")

    captured = capsys.readouterr()
    assert "group" in captured.out


def test_get_permissions_file_not_found(tmp_path, monkeypatch, capsys):
    """get_permissions shows error when file doesn't exist."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_get_permissions("nonexistent")

    captured = capsys.readouterr()
    assert "not a valid file" in captured.out


def test_get_permissions_no_filename(tmp_path, monkeypatch, capsys):
    """get_permissions shows error when no file name provided."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_get_permissions("")

    captured = capsys.readouterr()
    assert "File name is required" in captured.out


def test_get_permissions_default_is_user(tmp_path, monkeypatch, capsys):
    """Newly created file has default permission 'user'."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(tmp_path / "alice", "newfile", "alice"))

    shell.do_get_permissions("newfile")

    captured = capsys.readouterr()
    assert "user" in captured.out


def test_get_permissions_all_permission_types(tmp_path, monkeypatch, capsys):
    """get_permissions correctly returns all permission types."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    # Test user permission
    track_file(shell, File.create(tmp_path / "alice", "file1", "alice"))
    shell.do_set_permissions("file1 user")
    capsys.readouterr()  # Clear
    shell.do_get_permissions("file1")
    captured = capsys.readouterr()
    assert "user" in captured.out

    # Test group permission
    track_file(shell, File.create(tmp_path / "alice", "file2", "alice"))
    shell.do_set_permissions("file2 group")
    capsys.readouterr()  # Clear
    shell.do_get_permissions("file2")
    captured = capsys.readouterr()
    assert "group" in captured.out

    # Test all permission
    track_file(shell, File.create(tmp_path / "alice", "file3", "alice"))
    shell.do_set_permissions("file3 all")
    capsys.readouterr()  # Clear
    shell.do_get_permissions("file3")
    captured = capsys.readouterr()
    assert "all" in captured.out
