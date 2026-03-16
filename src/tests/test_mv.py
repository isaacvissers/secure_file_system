import backend.auth as auth
import main as main_module
from main import SecureFS
from models.directory import Directory
from models.file import File
from tests.encryption_helpers import track_file
from tests.path_helpers import encrypted_path
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch):
    """Return a SecureFS instance logged in with cwd inside FILES_DIR/alice."""
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


def test_mv_renames_file_in_current_directory(tmp_path, monkeypatch):
    """mv renames a file within the current directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "old", "alice"))

    shell.do_mv("old new")

    assert not encrypted_path(shell.current_working_directory, "old").exists()
    assert encrypted_path(shell.current_working_directory, "new").exists()


def test_mv_errors_when_source_missing(tmp_path, monkeypatch, capsys):
    """mv prints an error when source does not exist."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_mv("ghost new")

    captured = capsys.readouterr()
    assert "Source file 'ghost' does not exist" in captured.out


def test_mv_errors_when_destination_exists(tmp_path, monkeypatch, capsys):
    """mv prints an error when destination already exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "old", "alice"))
    track_file(shell, File.create(shell.current_working_directory, "new", "alice"))

    shell.do_mv("old new")

    captured = capsys.readouterr()
    assert "Destination file 'new' already exists" in captured.out


def test_mv_rejects_invalid_syntax(tmp_path, monkeypatch, capsys):
    """mv prints usage error when required arguments are missing."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_mv("only_source")

    captured = capsys.readouterr()
    assert "Invalid syntax" in captured.out


def test_mv_supports_quoted_names_with_spaces(tmp_path, monkeypatch):
    """mv supports quoted source/destination names containing spaces."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "old name", "alice"))

    shell.do_mv('"old name" "new name"')

    assert not encrypted_path(shell.current_working_directory, "old name").exists()
    assert encrypted_path(shell.current_working_directory, "new name").exists()


def test_mv_with_json_suffix_argument_is_not_supported(tmp_path, monkeypatch, capsys):
    """mv treats a .json suffix literally when looking up the source path."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "old", "alice"))

    shell.do_mv("old.json new")

    captured = capsys.readouterr()
    assert "Source file 'old.json' does not exist" in captured.out


def test_mv_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    """@requires_login prevents mv when no user is authenticated."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell = SecureFS()
    shell.current_working_directory = tmp_path

    shell.do_mv("old new")

    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out


def test_mv_invalid_syntax_does_not_change_existing_files(
    tmp_path, monkeypatch, capsys
):
    """mv with invalid syntax should not alter files in cwd."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    track_file(shell, File.create(shell.current_working_directory, "old", "alice"))
    original = sorted(p.name for p in shell.current_working_directory.iterdir())

    shell.do_mv("old")

    captured = capsys.readouterr()
    assert "Invalid syntax" in captured.out
    after = sorted(p.name for p in shell.current_working_directory.iterdir())
    assert after == original


def test_mv_updates_persisted_file_info_for_renamed_file(tmp_path, monkeypatch):
    """do_mv should remove old-path file_info and add a new-path entry for renamed files."""
    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    files_dir.mkdir()

    monkeypatch.setattr(auth, "USERS_DIR", users_dir)
    monkeypatch.setattr(auth, "FILES_DIR", files_dir)
    monkeypatch.setattr(main_module, "FILES_DIR", files_dir)

    admin_key = auth.get_admin_key()
    auth.save_user(
        admin_key,
        {
            "username": "admin",
            "file_keys": [],
            "user_keys": {"alice": "alice_key"},
            "group_keys": {},
        },
    )
    auth.save_user(
        "alice_key",
        {
            "username": "alice",
            "file_keys": {},
            "file_info": {},
            "group_keys": [],
        },
    )

    user_home = Directory.create(files_dir, "alice", "alice")

    shell = SecureFS()
    shell.current_user = auth.load_user("alice")
    shell.current_working_directory = user_home.path
    shell._update_prompt()

    File.create(shell.current_working_directory, "old", "alice")
    shell._refresh_current_user()

    old_path = encrypted_path(shell.current_working_directory, "old")
    new_path = encrypted_path(shell.current_working_directory, "new")

    assert str(old_path) in shell.current_user.get("file_info", {})

    shell.do_mv("old new")

    updated_user = auth.load_user("alice")
    assert updated_user is not None
    assert str(old_path) not in updated_user.get("file_info", {})
    assert str(old_path) not in updated_user.get("file_keys", {})

    new_entry = updated_user.get("file_info", {}).get(str(new_path))
    assert new_entry is not None
    assert new_entry == "new"
