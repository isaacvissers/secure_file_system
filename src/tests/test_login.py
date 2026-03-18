import hashlib

import main as main_module
from main import SecureFS
from models.directory import Directory
from models.file import File, Permission
from models.user import AdminUser, User
from tests.tamper_helpers import flip_last_hash_nibble
from tests.test_helpers import make_user


def _make_user_data(user_id: int = 1, username: str = "alice") -> User:
    _ = user_id
    return User(
        username=username,
        auth_salt="testsalt",
        auth_verifier=hashlib.sha256(f"pwtestsalt".encode("utf-8")).hexdigest(),
        path=None,
    )


def _user_record_path(base, username: str):
    return base / hashlib.sha256(username.encode("utf-8")).hexdigest()


def test_login_success(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(main_module, "USERS_DIR", tmp_path)
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path / "files")
    main_module.FILES_DIR.mkdir()

    user_path = _user_record_path(tmp_path, "alice")
    user = make_user(tmp_path, "alice", path=user_path)
    Directory.create(main_module.FILES_DIR, "alice", user)
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "pw"))

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_user is not None
    assert shell.current_user.username == "alice"
    assert shell.current_working_directory == (
        main_module.FILES_DIR / hashlib.sha256(b"alice").hexdigest()
    )
    assert shell.prompt == "SFS/alice> "
    assert "Login successful" in capsys.readouterr().out


def test_login_fails_when_user_not_found(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(main_module, "USERS_DIR", tmp_path)
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("ghost", "pw"))

    shell = SecureFS()
    shell.do_login("")

    out = capsys.readouterr().out
    assert "User 'ghost' does not exist" in out
    assert shell.current_user is None


def test_login_rejected_when_already_logged_in(capsys):
    shell = SecureFS()
    shell.current_user = _make_user_data(username="alice")

    shell.do_login("")

    assert "Already logged in" in capsys.readouterr().out


def test_login_aborts_when_credentials_prompt_returns_none(monkeypatch, capsys):
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: None)

    shell = SecureFS()
    shell.do_login("")

    assert shell.current_user is None
    assert capsys.readouterr().out == ""


def test_login_fails_on_wrong_password(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(main_module, "USERS_DIR", tmp_path)
    user_path = _user_record_path(tmp_path, "alice")
    make_user(tmp_path, "alice", path=user_path)
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "wrong"))

    shell = SecureFS()
    shell.do_login("")

    out = capsys.readouterr().out
    assert "Incorrect password" in out
    assert shell.current_user is None


def test_admin_login_uses_admin_loader(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(main_module, "USERS_DIR", tmp_path)
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path / "files")
    main_module.FILES_DIR.mkdir()

    admin_path = _user_record_path(tmp_path, "admin")
    admin = AdminUser(
        username="admin",
        auth_salt="testsalt",
        auth_verifier=hashlib.sha256(f"admintestsalt".encode("utf-8")).hexdigest(),
        path=admin_path,
    )
    admin_key = hashlib.sha256("admin_admin_psalt".encode("utf-8")).digest()
    admin._encryption_key = admin_key
    admin.save(admin_key)
    Directory.create(main_module.FILES_DIR, "admin", admin)
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("admin", "admin"))

    shell = SecureFS()
    shell.do_login("")

    assert isinstance(shell.current_user, AdminUser)
    assert "Welcome admin" in capsys.readouterr().out


def test_login_warns_with_decrypted_name_for_hash_only_tamper(
    monkeypatch, capsys, tmp_path
):
    users_dir = tmp_path / "users"
    files_dir = tmp_path / "files"
    users_dir.mkdir()
    files_dir.mkdir()
    monkeypatch.setattr(main_module, "USERS_DIR", users_dir)
    monkeypatch.setattr(main_module, "FILES_DIR", files_dir)

    user_path = _user_record_path(users_dir, "alice")
    user = make_user(users_dir, "alice", path=user_path)
    home = Directory.create(files_dir, "alice", user)
    file = File.create(
        home.path,
        "test.txt",
        user,
        body="original\n",
        permission=Permission.USER,
    )
    flip_last_hash_nibble(file.path)
    monkeypatch.setattr(main_module, "prompt_credentials", lambda: ("alice", "pw"))

    shell = SecureFS()
    shell.do_login("")

    out = capsys.readouterr().out
    assert "Warning: The following files may have been compromised:" in out
    assert "- alice/test.txt" in out
