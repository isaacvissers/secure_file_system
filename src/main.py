import cmd

from backend.auth import *
from backend.auth import _iter_user_records
from backend.cryptography_utils import *
from backend.group_utils import *
from cli_utils import *


class SecureFS(cmd.Cmd):
    def __init__(self):
        super().__init__()
        self.current_user = None
        self.current_working_directory = None
        self._update_prompt()

    def _update_prompt(self):
        """Update the interactive prompt to include the logged-in username."""
        if self.current_user and isinstance(self.current_user, dict):
            user = self.current_user.get("user_data")
            if user and isinstance(user, dict):
                username = user.get("username")
                if username:
                    self.prompt = f"SFS/{username}> "
                    return
        self.prompt = "SFS> "

    @requires_logged_out
    def do_login(self, arg):
        """
        Usage: login
        """
        credentials = prompt_credentials()
        if credentials is None:
            return
        username, password = credentials

        user_data = load_user(username)
        if not user_data:
            print("Error: User does not exist.")
            return

        salt = bytes.fromhex(user_data["salt"])
        stored_hash = bytes.fromhex(user_data["password_hash"])

        if not verify_password(password.encode(), salt, stored_hash):
            print("Error: Incorrect password.")
            return

        try:
            private_key = decrypt_private_key(user_data, password)
        except Exception:
            print("Error: Failed to unlock private key.")
            return

        self.current_user = {"user_data": user_data, "private_key": private_key}
        self.current_working_directory = f"user_{user_data['user_id']}"
        self._update_prompt()
        print(f"Login successful. Welcome {username}.")

    @requires_login
    def do_logout(self, arg):
        """
        Usage: logout
        """
        self.current_user = None
        self.current_working_directory = None
        self._update_prompt()
        print(f"Log Out successful.")

    @requires_admin
    def do_create_user(self, arg):
        """
        Usage: create_user
        """
        credentials = prompt_credentials()
        if credentials is None:
            return
        username, password = credentials

        created_user = create_user(username, password, is_admin=False)
        if created_user is None:
            print("Error: Username already exists.")
            return

        print(f"User created: {created_user['username']} ")

    @requires_admin
    def do_create_group(self, arg):
        """
        Usage: create_group
        """
        group_name = prompt_required_text("group name")
        if group_name is None:
            return

        create_group(group_name)
        print(f"Group created: {group_name}")

    @requires_admin
    def do_add_user_to_group(self, arg):
        """
        Usage: add_user_to_group
        """
        group_name = prompt_required_text("group name")
        if group_name is None:
            return

        username = prompt_required_text("username")
        if username is None:
            return

        user_data = load_user(username)
        if user_data is None:
            print(f"Error: User '{username}' does not exist.")
            return

        group_data = load_group(group_name)
        if group_data is None:
            print(f"Error: Group '{group_name}' does not exist.")
            return

        user_id = user_data["user_id"]

        added_to_group = add_user_to_group(group_name, user_id)
        if not added_to_group:
            print(f"Failed to add user '{username}' to group '{group_name}'.")
            return

        print(f"User '{username}' added to group '{group_name}'.")

    @requires_admin
    def do_remove_user_from_group(self, arg):
        """
        Usage: remove_user_from_group
        """
        group_name = prompt_required_text("group name")
        if group_name is None:
            return

        username = prompt_required_text("username")
        if username is None:
            return

        user_data = load_user(username)
        if user_data is None:
            print(f"Error: User '{username}' does not exist.")
            return

        group_data = load_group(group_name)
        if group_data is None:
            print(f"Error: Group '{group_name}' does not exist.")
            return

        user_id = user_data["user_id"]
        members = group_data.get("members", [])
        if user_id not in members:
            print(f"User '{username}' is not a member of group '{group_name}'.")
            return

        remove_user_from_group(group_name, user_id)
        print(f"User '{username}' removed from group '{group_name}'.")

    @requires_admin
    def do_list_users(self, arg):
        """
        Usage: list_users
        """
        print("Users:")
        for _, user_data in _iter_user_records():
            print(f" - {user_data['username']} (ID: {user_data['user_id']})")

    def do_exit(self, arg):
        return True


if __name__ == "__main__":
    SecureFS().cmdloop()
