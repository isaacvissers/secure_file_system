import json
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

SRC_DIR = Path(__file__).resolve().parents[1]
GROUPS_DIR = SRC_DIR / "storage/.groups"
GROUPS_DIR.mkdir(parents=True, exist_ok=True)


GroupsDict = Dict[str, Any]


def _iter_group_records() -> Iterator[Tuple[Path, GroupsDict]]:
    for file_path in GROUPS_DIR.glob("*.json"):
        with open(file_path, "r", encoding="utf-8") as file:
            yield file_path, json.load(file)


def _write_group_file(file_path: Path, group_dict: GroupsDict) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(group_dict, file)


def _find_group_by_name(name: str) -> Optional[GroupsDict]:
    for _, group_data in _iter_group_records():
        if group_data.get("group_name") == name:
            return group_data
    return None


def _next_group_id() -> int:
    highest_group_id = 0
    for _, group_data in _iter_group_records():
        group_id = group_data.get("group_id", 0)
        if isinstance(group_id, int) and group_id > highest_group_id:
            highest_group_id = group_id
    return highest_group_id + 1


def group_exists(name: str) -> bool:
    return _find_group_by_name(name) is not None


def save_group(group_dict: GroupsDict) -> None:
    group_file = GROUPS_DIR / f"group_{group_dict['group_name']}.json"
    _write_group_file(group_file, group_dict)


def load_group(name: str) -> Optional[GroupsDict]:
    return _find_group_by_name(name)


def create_group(name: str) -> Optional[GroupsDict]:
    if group_exists(name):
        print(f"Group '{name}' already exists.")
        return None

    group_dict = {
        "group_id": _next_group_id(),
        "group_name": name,
        "members": [],
        "file_access": [],
    }
    save_group(group_dict)
    return group_dict


def add_user_to_group(group_name: str, user_id: int) -> bool:
    group = load_group(group_name)
    if group is None:
        print(f"Group '{group_name}' does not exist.")
        return False

    if user_id in group["members"]:
        print(f"User '{user_id}' is already a member of '{group_name}'.")
        return False

    group["members"].append(user_id)
    save_group(group)
    return True


def remove_user_from_group(group_name: str, user_id: int) -> None:
    group = load_group(group_name)
    if group is None:
        return

    members = group.get("members", [])
    if user_id in members:
        members.remove(user_id)
        save_group(group)
