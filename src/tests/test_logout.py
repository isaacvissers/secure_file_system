# tests/test_logout.py
import hashlib
from types import SimpleNamespace

import pytest

import main as main_module
from backend.auth import FILES_DIR
from main import SecureFS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _logged_in_shell():
    """Return a SecureFS instance that is already logged in as 'alice'."""
    shell = SecureFS()
    shell.current_user = {
        "user_data": {
            "user_id": 1,
            "username": "alice",
            "is_admin": False,
        },
        "private_key": object(),
    }
    shell.current_working_directory = FILES_DIR / "alice"
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_logout_clears_current_user(capsys):
    shell = _logged_in_shell()
    shell.do_logout("")
    assert shell.current_user is None


def test_logout_clears_working_directory(capsys):
    shell = _logged_in_shell()
    shell.do_logout("")
    assert shell.current_working_directory is None


def test_logout_resets_prompt(capsys):
    shell = _logged_in_shell()
    assert shell.prompt == "SFS/alice> "
    shell.do_logout("")
    assert shell.prompt == "SFS> "


def test_logout_prints_success_message(capsys):
    shell = _logged_in_shell()
    shell.do_logout("")
    captured = capsys.readouterr()
    assert "Log Out successful" in captured.out


def test_logout_rejected_when_not_logged_in(capsys):
    shell = SecureFS()
    shell.do_logout("")
    captured = capsys.readouterr()
    assert "Must be logged in" in captured.out
    assert shell.current_user is None


def test_logout_does_not_print_success_when_not_logged_in(capsys):
    shell = SecureFS()
    shell.do_logout("")
    captured = capsys.readouterr()
    assert "Log Out successful" not in captured.out


def test_logout_leaves_shell_usable_for_new_login(monkeypatch):
    """After logout, the shell can login a new user with mocked auth."""
    shell = _logged_in_shell()
    shell.do_logout("")

    new_user_data = {"username": "bob"}

    # Fake admin record
    dummy_admin = SimpleNamespace(
        username="admin", user_keys={"bob": "fake_key"}, group_keys={}
    )

    # Patch names **in main_module** where SecureFS.do_login calls them
    monkeypatch.setattr(main_module, "get_admin_record", lambda: dummy_admin)
    monkeypatch.setattr(
        main_module.auth,
        "_resolve_user",
        lambda admin, username: ("fake_key", new_user_data),
    )
    monkeypatch.setattr(
        main_module.auth, "verify_user_password", lambda user, password: True
    )
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("bob", "pass"))

    shell.do_login("")

    assert shell.current_user is not None
    assert shell.current_user["username"] == "bob"
    bob_home = hashlib.sha256("bob".encode("utf-8")).hexdigest()
    assert shell.prompt == f"SFS/{bob_home}> "


def test_logout_idempotent_prompt_reset(capsys):
    """Calling _update_prompt after logout always restores the default prompt."""
    shell = _logged_in_shell()
    shell.do_logout("")
    shell._update_prompt()
    assert shell.prompt == "SFS> "
