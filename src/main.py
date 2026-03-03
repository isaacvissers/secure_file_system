import cmd

from backend.auth import *
from backend.group_utils import *
from cli_utils import *
from backend.cryptography_utils import *


class SecureFS(cmd.Cmd):
    prompt = "SFS> "

    def __init__(self):
        super().__init__()
        self.current_user = None

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

        self.current_user = user_data
        print(f"Login successful. Welcome {username}.")

    @requires_login
    def do_logout(self, arg):
        """
        Usage: logout
        """
        self.current_user = None
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

        is_admin = prompt_yes_no("admin")

        created_user = create_user(username, password, is_admin=is_admin)
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
        group_id = group_data["group_id"]

        added_to_group = add_user_to_group(group_name, user_id)
        if not added_to_group:
            print(f"Failed to add user '{username}' to group '{group_name}'.")
            return

        added_to_user = add_group_to_user(username, group_id)
        if added_to_user:
            print(f"User '{username}' added to group '{group_name}'.")
            return

        remove_user_from_group(group_name, user_id)
        print(f"Failed to add user '{username}' to group '{group_name}'.")

    def do_exit(self, arg):
        return True


if __name__ == "__main__":
    SecureFS().cmdloop()
