# tests/conftest.py or test_group_utils_temp.py
import tempfile
from pathlib import Path

import pytest

import backend.auth as auth
import backend.group_utils as group_utils


@pytest.fixture
def temp_storage(monkeypatch):
    """Use temporary directories for all storage and prevent real folder creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        users_dir = tmp_path / ".users"
        groups_dir = tmp_path / ".groups"
        files_dir = tmp_path / "files"  # mimic files storage
        users_dir.mkdir()
        groups_dir.mkdir()
        files_dir.mkdir()

        # Patch the module-level constants
        monkeypatch.setattr(auth, "USERS_DIR", users_dir)
        monkeypatch.setattr(group_utils, "GROUPS_DIR", groups_dir)
        monkeypatch.setattr(auth, "FILES_DIR", files_dir)

        # Patch file-path helpers to use temp dirs
        monkeypatch.setattr(
            auth, "_user_file_path", lambda user_key: users_dir / f"{user_key}.json"
        )
        monkeypatch.setattr(
            group_utils,
            "_group_file",
            lambda group_key: groups_dir / f"{group_key}.json",
        )

        # Patch create_user_directory to just create a temp folder or do nothing
        monkeypatch.setattr(
            auth,
            "create_user_directory",
            lambda user_key: files_dir / f"user_{user_key}",
        )

        yield users_dir, groups_dir, files_dir


@pytest.fixture
def admin_user(temp_storage):
    """Create admin user."""
    user = auth.create_user(auth.ADMIN, auth.ADMIN, is_admin=True)
    assert user is not None
    return auth.get_admin_record()


@pytest.fixture
def all_group(temp_storage, admin_user):
    """Create the 'all' group required for user creation."""
    group = group_utils.create_group("all")
    assert group is not None
    return group


@pytest.fixture
def normal_user(temp_storage, admin_user, all_group):
    """Create normal user."""
    user = auth.create_user("alice", "password123")
    assert user is not None
    return user


# -------------------------------
# Tests
# -------------------------------


def test_create_group(temp_storage, admin_user):
    group = group_utils.create_group("devs")
    assert group is not None
    assert group["group_name"] == "devs"
    assert group["members"] == {}
    assert group["file_access"] == []

    # Group key registered in admin
    admin = auth.get_admin_record()
    assert "devs" in admin.group_keys
    group_key = admin.group_keys["devs"]

    # Group file exists
    group_file = group_utils.GROUPS_DIR / f"{group_key}.json"
    assert group_file.exists()


def test_load_and_save_group(temp_storage, admin_user):
    group_utils.create_group("qa")
    admin = auth.get_admin_record()
    group_key = admin.group_keys["qa"]

    group = group_utils.load_group("qa")
    assert group["group_name"] == "qa"

    # Modify and save
    group["file_access"].append("file_1")
    group_utils.save_group(group_key, group)

    loaded = group_utils.load_group("qa")
    assert "file_1" in loaded["file_access"]


def test_add_user_to_group(temp_storage, admin_user, all_group, normal_user):
    group_utils.create_group("design")
    admin = auth.get_admin_record()
    group_key = admin.group_keys["design"]

    result = group_utils.add_user_to_group("design", "alice")
    assert result is True

    # Check group updated
    group = group_utils.load_group("design")
    user_key = admin.user_keys["alice"]
    assert user_key in group["members"]
    assert group["members"][user_key] == "alice"

    # Check user updated
    user = auth.load_user("alice")
    assert group_key in user["group_keys"]

    # Adding the same user again fails
    result2 = group_utils.add_user_to_group("design", "alice")
    assert result2 is False


def test_add_user_to_nonexistent_group(
    temp_storage, admin_user, all_group, normal_user
):
    result = group_utils.add_user_to_group("nonexistent", "alice")
    assert result is False


def test_add_nonexistent_user_to_group(temp_storage, admin_user):
    group_utils.create_group("ops")
    result = group_utils.add_user_to_group("ops", "bob")
    assert result is False


def test_new_user_automatically_added_to_all_group(temp_storage, admin_user, all_group):
    """Test that new users are automatically added to the 'all' group."""
    # Create a new user
    user = auth.create_user("bob", "password456")
    assert user is not None

    # Verify user was added to "all" group
    all_group_data = group_utils.load_group("all")
    admin = auth.get_admin_record()
    bob_user_key = admin.user_keys["bob"]
    assert bob_user_key in all_group_data["members"]
    assert all_group_data["members"][bob_user_key] == "bob"

    # Verify user's group_keys includes the "all" group
    bob_user = auth.load_user("bob")
    all_group_key = admin.group_keys["all"]
    assert all_group_key in bob_user["group_keys"]
