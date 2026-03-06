import main as main_module
from main import SecureFS
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch):
    """Return a SecureFS instance logged in with cwd inside FILES_DIR/alice."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    user_home = tmp_path / "alice"
    user_home.mkdir(exist_ok=True)
    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = user_home
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# Basic behaviour
# ---------------------------------------------------------------------------


def test_touch_creates_json_file(tmp_path, monkeypatch, capsys):
    """touch creates a <name>.json metadata file in current_working_directory."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "notes")

    shell.do_touch("")

    assert (tmp_path / "alice" / "notes.json").exists()
    captured = capsys.readouterr()
    assert "created" in captured.out


def test_touch_via_arg(tmp_path, monkeypatch, capsys):
    """touch accepts the file name directly as the arg string."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_touch("readme")

    assert (tmp_path / "alice" / "readme.json").exists()
    captured = capsys.readouterr()
    assert "created" in captured.out


def test_touch_via_prompt(tmp_path, monkeypatch, capsys):
    """touch prompts for a name when arg is empty."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module, "prompt_required_text", lambda label: "todo")

    shell.do_touch("")

    assert (tmp_path / "alice" / "todo.json").exists()


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
    (tmp_path / "alice" / "dup.json").write_text("{}")
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
    other_user = tmp_path / "bob"
    other_user.mkdir()

    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = other_user

    shell.do_touch("stolen")

    captured = capsys.readouterr()
    assert "Cannot create files outside of your home directory" in captured.out
    assert not (other_user / "stolen.json").exists()


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
    user_home = tmp_path / "alice"
    subdir = user_home / "documents"
    subdir.mkdir(parents=True)
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)

    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = subdir

    shell.do_touch("nested")

    captured = capsys.readouterr()
    assert "created" in captured.out
    assert (subdir / "nested.json").exists()
