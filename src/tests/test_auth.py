import json

from scripts import create_admin
from backend import auth


def test_save_user_writes_expected_json_file(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    user_dict = {
        "user_id": 42,
        "username": "alice",
        "salt": "abc",
        "password_hash": "def",
        "is_admin": False,
    }

    auth.save_user(user_dict)

    user_file = tmp_path / "user_42.json"
    assert user_file.exists()

    with open(user_file, "r") as file:
        saved_data = json.load(file)

    assert saved_data == user_dict


def test_user_exists_returns_true_when_username_present(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    with open(tmp_path / "user_1.json", "w") as file:
        json.dump({"user_id": 1, "username": "alice"}, file)

    with open(tmp_path / "user_2.json", "w") as file:
        json.dump({"user_id": 2, "username": "bob"}, file)

    assert auth.user_exists("alice") is True


def test_user_exists_returns_false_when_username_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    with open(tmp_path / "user_1.json", "w") as file:
        json.dump({"user_id": 1, "username": "alice"}, file)

    assert auth.user_exists("charlie") is False


def test_load_user_returns_user_by_username(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    user = {
        "user_id": 7,
        "username": "dana",
        "salt": "aa",
        "password_hash": "bb",
        "is_admin": False,
    }
    with open(tmp_path / "user_7.json", "w") as file:
        json.dump(user, file)

    loaded = auth.load_user("dana")

    assert loaded == user


def test_create_user_saves_user_with_hashed_password(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    created = auth.create_user("eve", "secret", is_admin=True)

    assert created is not None
    assert created["username"] == "eve"
    assert created["is_admin"] is True
    assert len(created["salt"]) == 32
    assert len(created["password_hash"]) == 64

    user_file = tmp_path / f"user_{created['user_id']}.json"
    assert user_file.exists()


def test_create_user_returns_none_when_username_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    with open(tmp_path / "user_1.json", "w") as file:
        json.dump({"user_id": 1, "username": "frank"}, file)

    created = auth.create_user("frank", "another-secret")

    assert created is None


def test_add_group_to_user_appends_group_id(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    with open(tmp_path / "user_1.json", "w", encoding="utf-8") as file:
        json.dump(
            {
                "user_id": 1,
                "username": "alice",
                "salt": "aa",
                "password_hash": "bb",
                "is_admin": False,
                "group_ids": [],
            },
            file,
        )

    added = auth.add_group_to_user("alice", 5)

    assert added is True
    updated_user = auth.load_user("alice")
    assert updated_user is not None
    assert 5 in updated_user["group_ids"]


def test_add_group_to_user_returns_false_for_missing_user(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    added = auth.add_group_to_user("ghost", 2)

    assert added is False


def test_add_group_to_user_returns_false_when_group_already_present(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)

    with open(tmp_path / "user_1.json", "w", encoding="utf-8") as file:
        json.dump(
            {
                "user_id": 1,
                "username": "alice",
                "salt": "aa",
                "password_hash": "bb",
                "is_admin": False,
                "group_ids": [9],
            },
            file,
        )

    added = auth.add_group_to_user("alice", 9)

    assert added is False


def test_ensure_admin_user_resets_password_when_requested(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_DIR", tmp_path)
    monkeypatch.setattr(create_admin, "USERS_DIR", tmp_path)

    with open(tmp_path / "user_1.json", "w") as file:
        json.dump(
            {
                "user_id": 1,
                "username": "admin",
                "salt": "aa",
                "password_hash": "bb",
                "is_admin": True,
            },
            file,
        )

    user_data, status = create_admin.ensure_admin_user(
        "admin", "new-password", reset_password=True
    )

    assert status == "updated"
    assert user_data["salt"] != "aa"
    assert user_data["password_hash"] != "bb"
