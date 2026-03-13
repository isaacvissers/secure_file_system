import main as main_module
from main import SecureFS
from models.directory import Directory
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
# Basic behaviour
# ---------------------------------------------------------------------------


def test_touch_creates_file(tmp_path, monkeypatch, capsys):
    """touch creates a plain file in current_working_directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "notes")

    shell.do_touch("")

    assert encrypted_path(shell.current_working_directory, "notes").exists()
    captured = capsys.readouterr()
    assert "created" in captured.out


def test_touch_via_arg(tmp_path, monkeypatch, capsys):
    """touch accepts the file name directly as the arg string."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_touch("readme")

    assert encrypted_path(shell.current_working_directory, "readme").exists()
    captured = capsys.readouterr()
    assert "created" in captured.out


def test_touch_via_prompt(tmp_path, monkeypatch, capsys):
    """touch prompts for a name when arg is empty."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "todo")

    shell.do_touch("")

    assert encrypted_path(shell.current_working_directory, "todo").exists()


def test_touch_prints_success_message(tmp_path, monkeypatch, capsys):
    """touch prints a confirmation containing the file name."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "report")

    shell.do_touch("")

    captured = capsys.readouterr()
    assert "report" in captured.out
    assert "created" in captured.out


def test_touch_error_when_file_already_exists(tmp_path, monkeypatch, capsys):
    """touch prints an error without raising when the file already exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    encrypted_path(shell.current_working_directory, "dup").write_text("{}")
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "dup")

    shell.do_touch("")

    captured = capsys.readouterr()
    assert "Error" in captured.out
    assert "created" not in captured.out


def test_touch_aborts_when_name_is_empty(tmp_path, monkeypatch, capsys):
    """touch returns early when prompt_required_text returns None."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: None)

    shell.do_touch("")

    assert list(shell.current_working_directory.iterdir()) == []


def test_touch_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    """@requires_login prevents touch when no user is authenticated."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell = SecureFS()
    shell.current_working_directory = tmp_path

    shell.do_touch("secret")

    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Home directory boundary tests
# ---------------------------------------------------------------------------


def test_touch_blocked_outside_home_directory(tmp_path, monkeypatch, capsys):
    """touch rejects file creation when cwd is outside the user's home directory."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    other_user = encrypted_path(tmp_path, "bob")
    other_user.mkdir()

    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = other_user

    shell.do_touch("stolen")

    captured = capsys.readouterr()
    assert "Cannot create files outside of your home directory" in captured.out
    assert not encrypted_path(other_user, "stolen").exists()


def test_touch_blocked_at_files_dir_root(tmp_path, monkeypatch, capsys):
    """touch rejects file creation when cwd is FILES_DIR itself."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = tmp_path

    shell.do_touch("intruder")

    captured = capsys.readouterr()
    assert "Cannot create files outside of your home directory" in captured.out


def test_touch_allowed_in_subdirectory_of_home(tmp_path, monkeypatch, capsys):
    """touch succeeds when cwd is a subdirectory inside the user's home."""
    user_home = Directory.create(tmp_path, "alice", "alice")
    subdir = Directory.create(user_home.path, "documents", "alice")
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_user["file_keys"][
        str(user_home.metadata.path)
    ] = user_home.metadata.encrypted_file_key.hex()
    shell.current_user["file_keys"][
        str(subdir.metadata.path)
    ] = subdir.metadata.encrypted_file_key.hex()
    shell.current_working_directory = subdir.path

    shell.do_touch("nested")

    captured = capsys.readouterr()
    assert "created" in captured.out
    assert encrypted_path(subdir.path, "nested").exists()
