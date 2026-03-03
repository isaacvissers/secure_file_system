import json

from backend import group_utils


def test_save_group_writes_expected_json_file(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    group_dict = {
        "group_id": 10,
        "group_name": "eng-team",
        "members": ["alice"],
        "file_access": ["file_1"],
    }

    group_utils.save_group(group_dict)

    group_file = tmp_path / "group_eng-team.json"
    assert group_file.exists()

    with open(group_file, "r", encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data == group_dict


def test_group_exists_returns_true_when_group_present(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    with open(tmp_path / "group_eng-team.json", "w", encoding="utf-8") as file:
        json.dump({"group_id": 1, "group_name": "eng-team"}, file)

    assert group_utils.group_exists("eng-team") is True


def test_group_exists_returns_false_when_group_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    with open(tmp_path / "group_design.json", "w", encoding="utf-8") as file:
        json.dump({"group_id": 1, "group_name": "design"}, file)

    assert group_utils.group_exists("eng-team") is False


def test_load_group_returns_group_by_name(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    group = {
        "group_id": 5,
        "group_name": "research",
        "members": ["alice", "bob"],
        "file_access": [],
    }
    with open(tmp_path / "group_research.json", "w", encoding="utf-8") as file:
        json.dump(group, file)

    loaded = group_utils.load_group("research")

    assert loaded == group


def test_create_group_creates_new_group_with_expected_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    created = group_utils.create_group("admins")

    assert created is not None
    assert created["group_name"] == "admins"
    assert created["members"] == []
    assert created["file_access"] == []

    group_file = tmp_path / "group_admins.json"
    assert group_file.exists()


def test_create_group_returns_none_when_group_already_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    with open(tmp_path / "group_admins.json", "w", encoding="utf-8") as file:
        json.dump({"group_id": 1, "group_name": "admins"}, file)

    created = group_utils.create_group("admins")

    assert created is None


def test_add_user_to_group_adds_member(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    with open(tmp_path / "group_admins.json", "w", encoding="utf-8") as file:
        json.dump(
            {
                "group_id": 1,
                "group_name": "admins",
                "members": [],
                "file_access": [],
            },
            file,
        )

    added = group_utils.add_user_to_group("admins", 42)

    assert added is True
    updated = group_utils.load_group("admins")
    assert updated is not None
    assert 42 in updated["members"]


def test_add_user_to_group_returns_false_for_missing_group(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    added = group_utils.add_user_to_group("missing", 1)

    assert added is False


def test_add_user_to_group_returns_false_for_duplicate_member(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    with open(tmp_path / "group_admins.json", "w", encoding="utf-8") as file:
        json.dump(
            {
                "group_id": 1,
                "group_name": "admins",
                "members": [7],
                "file_access": [],
            },
            file,
        )

    added = group_utils.add_user_to_group("admins", 7)

    assert added is False


def test_remove_user_from_group_removes_member(tmp_path, monkeypatch):
    monkeypatch.setattr(group_utils, "GROUPS_DIR", tmp_path)

    with open(tmp_path / "group_admins.json", "w", encoding="utf-8") as file:
        json.dump(
            {
                "group_id": 1,
                "group_name": "admins",
                "members": [3, 8],
                "file_access": [],
            },
            file,
        )

    group_utils.remove_user_from_group("admins", 3)

    updated = group_utils.load_group("admins")
    assert updated is not None
    assert 3 not in updated["members"]
    assert 8 in updated["members"]
