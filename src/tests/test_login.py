# tests/test_login_safe.py
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import backend.auth as auth
import main as main_module
from backend.auth import FILES_DIR
from main import SecureFS

# ---------------------------
# Fixtures
# ---------------------------


@pytest.fixture
def temp_files_dir(monkeypatch):
    """Redirect FILES_DIR to a temporary folder and patch create_user_key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # Patch FILES_DIR everywhere it's used
        monkeypatch.setattr(auth, "FILES_DIR", tmp_path)
        monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
        # Patch create_user_key to return the username for simplicity
        monkeypatch.setattr(
            auth, "create_user_key", lambda username, password: username
        )
        monkeypatch.setattr(
            main_module, "create_user_key", lambda username, password: username
        )
        yield tmp_path


def _make_user(username="alice"):
    """Return a minimal user dictionary."""
    return {"username": username}


def _make_user_data(user_id: int = 1, username: str = "alice"):
    """Return a user dict including `user_id` and `username` for tests that need it."""
    return {"user_id": user_id, "username": username}


# ---------------------------
# Tests
# ---------------------------


def test_login_success(monkeypatch, capsys, temp_files_dir):
    """Successful login sets current_user, working directory, and prompt."""
    user_data = _make_user("alice")

    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "pass"))
    monkeypatch.setattr(main_module, "load_user", lambda username: user_data)
    monkeypatch.setattr(
        main_module,
        "get_admin_record",
        lambda: SimpleNamespace(user_keys={"alice": "alice"}),
    )
    monkeypatch.setattr(
        auth, "_resolve_user", lambda admin, username: ("alice", user_data)
    )

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_user is not None
    assert shell.current_working_directory == temp_files_dir / "alice"
    assert shell.current_user == user_data
    assert shell.prompt == "SFS/alice> "
    captured = capsys.readouterr()
    assert "Login successful" in captured.out


def test_login_fails_when_user_not_found(monkeypatch, capsys, temp_files_dir):
    """Login prints an error and returns early when the user does not exist."""
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("ghost", "pw"))
    monkeypatch.setattr(main_module, "load_user", lambda username: None)
    monkeypatch.setattr(
        main_module, "get_admin_record", lambda: SimpleNamespace(user_keys={})
    )

    shell = SecureFS()
    shell.do_login("")

    captured = capsys.readouterr()
    assert "does not exist" in captured.out
    assert shell.current_user is None


def test_login_rejected_when_already_logged_in(monkeypatch, capsys, temp_files_dir):
    """A logged-in user cannot overwrite the session with a second login call."""
    shell = SecureFS()
    shell.current_user = {"username": "alice"}

    shell.do_login("")  # should be blocked

    captured = capsys.readouterr()
    assert "Already logged in" in captured.out
    assert shell.current_user is not None


def test_login_aborts_when_credentials_prompt_returns_none(
    monkeypatch, capsys, temp_files_dir
):
    """Login returns early without error when prompt_credentials returns None."""
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: None)

    shell = SecureFS()
    shell.do_login("")

    captured = capsys.readouterr()
    assert shell.current_user is None
    # Should not print any "does not exist" or "Incorrect" messages
    assert "does not exist" not in captured.out
    assert "Incorrect" not in captured.out


def test_login_sets_correct_working_directory(monkeypatch, temp_files_dir):
    """current_working_directory is set to FILES_DIR/username after login."""
    user_data = _make_user("carol")
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("carol", "pass"))
    monkeypatch.setattr(
        main_module,
        "get_admin_record",
        lambda: SimpleNamespace(user_keys={"carol": "carol"}),
    )
    monkeypatch.setattr(
        auth, "_resolve_user", lambda admin, username: ("carol", user_data)
    )

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_working_directory == temp_files_dir / "carol"


def test_login_does_not_overwrite_existing_session(monkeypatch, capsys):
    """A logged-in user cannot overwrite the session with a second login call."""
    original_user = {
        "user_data": _make_user_data(username="first"),
        "private_key": object(),
    }

    shell = SecureFS()
    shell.current_user = original_user

    # requires_logged_out decorator should block any new login
    shell.do_login("")

    captured = capsys.readouterr()
    assert "Already logged in" in captured.out
    assert shell.current_user is original_user


def test_login_fails_when_admin_missing(monkeypatch, capsys):
    """Login fails gracefully if admin record is missing."""
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "pass"))
    monkeypatch.setattr(main_module, "load_user", lambda username: _make_user("alice"))
    monkeypatch.setattr(main_module, "get_admin_record", lambda: None)  # No admin

    shell = SecureFS()
    shell.do_login("")

    captured = capsys.readouterr()
    assert "Admin record missing" in captured.out
    assert shell.current_user is None


def test_login_password_branch(monkeypatch, capsys, temp_files_dir):
    """Simulate wrong password / placeholder logic."""
    user_data = _make_user("alice")
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "wrong"))
    monkeypatch.setattr(main_module, "load_user", lambda username: user_data)
    monkeypatch.setattr(
        main_module,
        "get_admin_record",
        lambda: SimpleNamespace(user_keys={"alice": "alice"}),
    )
    monkeypatch.setattr(
        auth, "_resolve_user", lambda admin, username: ("alice", user_data)
    )
    monkeypatch.setattr(
        auth, "create_user_key", lambda username, password: "alice"
    )  # bypass password check

    shell = SecureFS()
    shell.do_login("")

    # Should succeed because current placeholder logic does not verify password
    assert shell.current_user == user_data
    assert shell.prompt == "SFS/alice> "
