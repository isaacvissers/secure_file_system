import main as main_module
from backend.auth import FILES_DIR
from main import SecureFS
from models.directory import Directory
from tests.path_helpers import encrypted_name, encrypted_path
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


def test_mkdir_creates_directory(tmp_path, monkeypatch, capsys):
    """mkdir creates the requested directory inside current_working_directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "docs")

    shell.do_mkdir("")

    assert encrypted_path(shell.current_working_directory, "docs").is_dir()
    captured = capsys.readouterr()
    assert "created" in captured.out


def test_mkdir_prints_success_message(tmp_path, monkeypatch, capsys):
    """mkdir prints a confirmation containing the directory name."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "reports")

    shell.do_mkdir("")

    captured = capsys.readouterr()
    assert "reports" in captured.out
    assert "created" in captured.out


def test_mkdir_error_when_directory_already_exists(tmp_path, monkeypatch, capsys):
    """mkdir prints an error and does not raise when the directory already exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    encrypted_path(shell.current_working_directory, "photos").mkdir(parents=True)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "photos")

    shell.do_mkdir("")

    captured = capsys.readouterr()
    assert "already exists" in captured.out
    assert "created" not in captured.out


def test_mkdir_does_not_overwrite_existing_directory(tmp_path, monkeypatch, capsys):
    """An existing directory is left untouched when mkdir is blocked."""
    vault = tmp_path / "alice" / "vault"
    vault.mkdir(parents=True)
    sentinel = vault / "sentinel.txt"
    sentinel.write_text("keep me")

    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "vault")

    shell.do_mkdir("")

    assert sentinel.exists()


def test_mkdir_blocked_when_not_logged_in(tmp_path, monkeypatch, capsys):
    """@requires_login prevents mkdir when no user is authenticated."""
    shell = SecureFS()
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    shell.current_working_directory = tmp_path

    shell.do_mkdir("")

    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out
    assert list(tmp_path.iterdir()) == []


def test_mkdir_aborts_when_name_is_empty(tmp_path, monkeypatch, capsys):
    """mkdir returns early (no directory created) when prompt_required_text returns None."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: None)

    shell.do_mkdir("")

    # Only the home dir itself should exist, nothing extra
    assert list(shell.current_working_directory.iterdir()) == []


def test_mkdir_creates_directory_in_cwd(tmp_path, monkeypatch):
    """The new directory is a direct child of current_working_directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "archive")

    shell.do_mkdir("")

    expected = encrypted_path(shell.current_working_directory, "archive")
    assert expected.exists() and expected.is_dir()


def test_mkdir_multiple_distinct_directories(tmp_path, monkeypatch, capsys):
    """Each mkdir call for a unique name succeeds independently."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    for name in ("alpha", "beta", "gamma"):
        monkeypatch.setattr(
            main_module, "prompt_required_text", lambda label, n=name: n
        )
        shell.do_mkdir("")

    dirs = {p.name for p in shell.current_working_directory.iterdir() if p.is_dir()}
    assert dirs == {
        encrypted_name("alpha"),
        encrypted_name("beta"),
        encrypted_name("gamma"),
    }


# ---------------------------------------------------------------------------
# Home directory boundary tests
# ---------------------------------------------------------------------------


def test_mkdir_blocked_outside_home_directory(tmp_path, monkeypatch, capsys):
    """mkdir rejects creation when cwd is outside the user's home directory."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    other_user = encrypted_path(tmp_path, "bob")
    other_user.mkdir()

    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    # cwd is bob's directory, not alice's
    shell.current_working_directory = other_user

    shell.do_mkdir("secret")

    captured = capsys.readouterr()
    assert "Cannot create directories outside of your home directory" in captured.out
    assert not (other_user / "secret").exists()


def test_mkdir_blocked_at_files_dir_root(tmp_path, monkeypatch, capsys):
    """mkdir rejects creation when cwd is FILES_DIR itself (not inside a user home)."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = tmp_path  # FILES_DIR root, not alice's home

    shell.do_mkdir("intruder")

    captured = capsys.readouterr()
    assert "Cannot create directories outside of your home directory" in captured.out


def test_mkdir_allowed_in_subdirectory_of_home(tmp_path, monkeypatch, capsys):
    """mkdir succeeds when cwd is a subdirectory inside the user's home."""
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

    shell.do_mkdir("nested")

    captured = capsys.readouterr()
    assert "created" in captured.out
    assert encrypted_path(subdir.path, "nested").is_dir()
