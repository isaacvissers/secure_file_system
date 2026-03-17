import backend.group_utils as group_utils
from models.group import Group
from models.user import User


def make_group(tmp_path, name="devs"):
    group_key = "ab" * 32
    group = Group(
        group_name=name,
        encrypted_name=name,
        members={},
        file_access={},
        path=tmp_path / f"{name}.json",
    )
    group.save()
    return group, group_key


def make_user(tmp_path, username="alice"):
    user = User(username=username, path=tmp_path / f"{username}.json")
    user.save()
    return user


def test_get_groups_by_user_returns_existing_groups(tmp_path):
    user = make_user(tmp_path)
    group, group_key = make_group(tmp_path, "devs")
    user.group_keys[str(group.path)] = {"id": str(group.path), "key": group_key}

    groups = group_utils.get_groups_by_user(user)

    assert [g.group_name for g in groups] == ["devs"]


def test_get_specific_group_for_user_returns_match(tmp_path):
    user = make_user(tmp_path)
    group, group_key = make_group(tmp_path, "ops")
    user.group_keys[str(group.path)] = {"id": str(group.path), "key": group_key}

    result = group_utils.get_specific_group_for_user(user, "ops")

    assert result is not None
    assert result.group_name == "ops"


def test_add_user_to_group_updates_members(tmp_path):
    user = make_user(tmp_path)
    group, _ = make_group(tmp_path)

    assert group_utils.add_user_to_group(user, group) is True
    assert group.members[user.get_encrypted_name()] == user.username


def test_add_group_to_user_stores_group_access(tmp_path):
    user = make_user(tmp_path)
    group, group_key = make_group(tmp_path)

    assert group_utils.add_group_to_user(user, group, group_key) is True
    assert user.group_keys["devs"]["id"] == str(group.path)
    assert user.group_keys["devs"]["key"] == group_key


def test_remove_user_from_group_removes_member(tmp_path):
    user = make_user(tmp_path)
    group, _ = make_group(tmp_path)
    group.members[user.get_encrypted_name()] = user.username

    assert group_utils.remove_user_from_group(user, group) is True
    assert user.get_encrypted_name() not in group.members


def test_remove_group_from_user_missing_entry_returns_false(tmp_path, capsys):
    user = make_user(tmp_path)
    group, _ = make_group(tmp_path)

    assert group_utils.remove_group_from_user(user, group) is False
    assert "not found in user's profile" in capsys.readouterr().out
