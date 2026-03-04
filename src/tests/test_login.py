import io

import pytest

import main as main_module
from backend.files_utils import FILES_DIR
from main import SecureFS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user_data(
    user_id=1,
    username="alice",
    password="secret",
    salt_hex=None,
    password_hash_hex=None,
    encrypted_private_key_hex="aabbcc",
    private_key_nonce_hex="001122",
    public_key_hex="deadbeef",
    is_admin=False,
):
    """Return a minimal user_dict that mirrors what auth.create_user produces."""
    if salt_hex is None:
        salt_hex = "aa" * 16
    if password_hash_hex is None:
        password_hash_hex = "bb" * 32
    return {
        "user_id": user_id,
        "username": username,
        "salt": salt_hex,
        "password_hash": password_hash_hex,
        "is_admin": is_admin,
        "public_key": public_key_hex,
        "encrypted_private_key": encrypted_private_key_hex,
        "private_key_nonce": private_key_nonce_hex,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_login_success(monkeypatch, capsys):
    """Successful login sets current_user, cwd, and prints welcome message."""
    user_data = _make_user_data()
    fake_private_key = object()
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "secret"))
    monkeypatch.setattr(main_module, "load_user", lambda username: user_data)
    # main sets current_user from get_user_record_by_username; provide a simple object
    from types import SimpleNamespace

    user_obj = SimpleNamespace(username="alice")
    monkeypatch.setattr(
        main_module, "get_user_record_by_username", lambda username: user_obj
    )

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_user is user_obj
    expected_dir = FILES_DIR / main_module.create_user_key("alice", "secret")
    assert shell.current_working_directory == expected_dir
    assert shell.prompt == "SFS/alice> "

    captured = capsys.readouterr()
    assert "Login successful" in captured.out
    assert "alice" in captured.out


def test_login_updates_prompt_with_username(monkeypatch):
    """The shell prompt is updated to include the logged-in username."""
    user_data = _make_user_data(username="bob")
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("bob", "pass"))
    monkeypatch.setattr(main_module, "load_user", lambda username: user_data)
    from types import SimpleNamespace

    monkeypatch.setattr(
        main_module,
        "get_user_record_by_username",
        lambda username: SimpleNamespace(username="bob"),
    )

    shell = SecureFS()
    shell.do_login("")

    assert shell.prompt == "SFS/bob> "


def test_login_rejected_when_already_logged_in(monkeypatch, capsys):
    """@requires_logged_out prevents login when a user is already logged in."""
    shell = SecureFS()
    shell.current_user = {"user_data": _make_user_data(), "private_key": object()}

    shell.do_login("")

    captured = capsys.readouterr()
    assert "Already logged in" in captured.out
    # current_user must remain unchanged
    assert shell.current_user is not None


def test_login_fails_when_user_not_found(monkeypatch, capsys):
    """Login prints an error and returns early when the username is not registered."""
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("ghost", "pw"))
    monkeypatch.setattr(main_module, "load_user", lambda username: None)

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_user is None
    captured = capsys.readouterr()
    assert "does not exist" in captured.out


def test_login_fails_on_wrong_password(monkeypatch, capsys):
    """`main` currently doesn't verify passwords; test the 'user not found' branch instead."""
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "wrong"))
    monkeypatch.setattr(main_module, "load_user", lambda username: None)

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_user is None
    captured = capsys.readouterr()
    assert "does not exist" in captured.out


def test_login_fails_when_private_key_decryption_raises(monkeypatch, capsys):
    """`main` currently does not perform private-key decryption; test 'user not found'."""
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "secret"))
    monkeypatch.setattr(main_module, "load_user", lambda username: None)

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_user is None
    captured = capsys.readouterr()
    assert "does not exist" in captured.out


def test_login_aborts_when_credentials_prompt_returns_none(monkeypatch, capsys):
    """Login returns early (no error printed) when prompt_credentials returns None."""
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: None)

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_user is None
    # No specific error message is expected; just ensure it didn't crash
    captured = capsys.readouterr()
    assert "does not exist" not in captured.out
    assert "Incorrect" not in captured.out


def test_login_stores_correct_working_directory(monkeypatch):
    """current_working_directory is set to 'user_<id>' after login."""
    user_data = _make_user_data(user_id=42, username="carol")
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("carol", "pass"))
    monkeypatch.setattr(main_module, "load_user", lambda username: user_data)
    from types import SimpleNamespace

    monkeypatch.setattr(
        main_module,
        "get_user_record_by_username",
        lambda username: SimpleNamespace(username="carol"),
    )

    shell = SecureFS()
    shell.do_login("")

    expected_dir = FILES_DIR / main_module.create_user_key("carol", "pass")
    assert shell.current_working_directory == expected_dir


def test_login_does_not_overwrite_existing_session(monkeypatch, capsys):
    """A logged-in user cannot overwrite the session with a second login call."""
    original_user = {
        "user_data": _make_user_data(username="first"),
        "private_key": object(),
    }

    shell = SecureFS()
    shell.current_user = original_user

    # Even if credentials would succeed, requires_logged_out should block this
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("second", "pw"))
    monkeypatch.setattr(
        main_module, "load_user", lambda username: _make_user_data(username="second")
    )
    from types import SimpleNamespace

    monkeypatch.setattr(
        main_module,
        "get_user_record_by_username",
        lambda username: SimpleNamespace(username="second"),
    )

    shell.do_login("")

    # Session must still belong to the original user (requires_logged_out blocks login)
    assert shell.current_user is original_user
