import pytest

import main as main_module
from backend.files_utils import FILES_DIR
from main import SecureFS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _logged_in_shell():
    """Return a SecureFS instance that is already in a logged-in state."""
    shell = SecureFS()
    from types import SimpleNamespace

    shell.current_user = SimpleNamespace(username="alice")
    shell.current_working_directory = FILES_DIR / "user_1"
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_logout_clears_current_user(capsys):
    """Successful logout sets current_user to None."""
    shell = _logged_in_shell()
    shell.do_logout("")

    assert shell.current_user is None


def test_logout_clears_working_directory(capsys):
    """Successful logout sets current_working_directory to None."""
    shell = _logged_in_shell()
    shell.do_logout("")

    assert shell.current_working_directory is None


def test_logout_resets_prompt(capsys):
    """Prompt returns to the default 'SFS> ' after logout."""
    shell = _logged_in_shell()
    assert shell.prompt == "SFS/alice> "

    shell.do_logout("")

    assert shell.prompt == "SFS> "


def test_logout_prints_success_message(capsys):
    """Logout prints a success message."""
    shell = _logged_in_shell()
    shell.do_logout("")

    captured = capsys.readouterr()
    assert "Log Out successful" in captured.out


def test_logout_rejected_when_not_logged_in(capsys):
    """@requires_login blocks logout when no user is authenticated."""
    shell = SecureFS()
    assert shell.current_user is None

    shell.do_logout("")

    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out


def test_logout_does_not_print_success_when_not_logged_in(capsys):
    """No success message is printed when logout is blocked."""
    shell = SecureFS()
    shell.do_logout("")

    captured = capsys.readouterr()
    assert "Log Out successful" not in captured.out


def test_logout_leaves_shell_usable_for_new_login(monkeypatch, capsys):
    """After logout the shell accepts a fresh login."""
    shell = _logged_in_shell()
    shell.do_logout("")

    new_user_data = {
        "user_id": 2,
        "username": "bob",
        "salt": "aa" * 16,
        "password_hash": "bb" * 32,
        "is_admin": False,
        "public_key": "dead",
        "encrypted_private_key": "beef",
        "private_key_nonce": "cafe",
    }
    fake_key = object()

    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("bob", "pass"))
    monkeypatch.setattr(main_module, "load_user", lambda username: new_user_data)
    from types import SimpleNamespace

    monkeypatch.setattr(
        main_module,
        "get_user_record_by_username",
        lambda username: SimpleNamespace(username="bob"),
    )

    shell.do_login("")

    assert shell.current_user is not None
    assert getattr(shell.current_user, "username", None) == "bob"
    assert shell.prompt == "SFS/bob> "


def test_logout_idempotent_prompt_reset(capsys):
    """Calling _update_prompt after logout always restores the default prompt."""
    shell = _logged_in_shell()
    shell.do_logout("")

    # Calling _update_prompt again should not raise and prompt stays default
    shell._update_prompt()
    assert shell.prompt == "SFS> "
