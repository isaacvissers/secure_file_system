import cmd

from backend.auth import *
from backend.cryptography_utils import *
from backend.files_utils import FILES_DIR
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
        if not self.current_user:
            self.prompt = "SFS> "
            return

        # support both dataclass-like objects and the dict-shaped session
        username = None
        if isinstance(self.current_user, dict):
            ud = self.current_user.get("user_data") or self.current_user
            if isinstance(ud, dict):
                username = ud.get("username")
            else:
                username = getattr(ud, "username", None)
        else:
            username = getattr(self.current_user, "username", None)

        if isinstance(username, str):
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

        admin = get_admin_record()
        if not admin:
            print("Error: Admin record missing.")
            return

        if username == ADMIN:
            # Use the AdminUser object for admin login
            expected_key = auth.create_user_key(username, password)
            admin_key = auth.get_admin_key()
            if expected_key != admin_key:
                print("Error: Incorrect password.")
                return
            self.current_user = admin
            # set working directory for admin session
            self.current_working_directory = FILES_DIR / username
        else:
            user_key, user_dict = auth._resolve_user(admin, username)
            if not user_dict:
                print(f"Error: User '{username}' does not exist.")
                return

            expected_key = auth.create_user_key(username, password)
            if user_key != expected_key:
                print("Error: Incorrect password.")
                return

            self.current_user = user_dict
            # set working directory to the user's files directory
            self.current_working_directory = FILES_DIR / username

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

    @requires_login
    def do_mkdir(self, arg):
        """
        Usage: mkdir <directory_name>
        """
        directory_name = prompt_required_text("directory name")
        if directory_name is None:
            return

        directory_path = self.current_working_directory / directory_name
        if directory_path.exists():
            print(f"Error: Directory '{directory_name}' already exists.")
            return
        directory_path.mkdir(parents=True, exist_ok=False)
        print(f"Directory '{directory_name}' created.")

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

        print(f"User created: {username} ")

    @requires_admin
    def do_create_group(self, arg):
        """
        Usage: create_group
        """
        group_name = prompt_required_text("group name")
        if group_name is None:
            return

        created = create_group(group_name)
        if created is None:
            return
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

        added_to_group = add_user_to_group(group_name, username)
        if not added_to_group:
            print(f"Failed to add user '{username}' to group '{group_name}'.")
            return

        print(f"User '{username}' added to group '{group_name}'.")

    # @requires_admin
    # def do_remove_user_from_group(self, arg):
    #     """
    #     Usage: remove_user_from_group
    #     """
    #     group_name = prompt_required_text("group name")
    #     if group_name is None:
    #         return

    #     username = prompt_required_text("username")
    #     if username is None:
    #         return

    #     user_data = load_user(username)
    #     if user_data is None:
    #         print(f"Error: User '{username}' does not exist.")
    #         return

    #     group_data = load_group(group_name)
    #     if group_data is None:
    #         print(f"Error: Group '{group_name}' does not exist.")
    #         return

    #     user_id = user_data["user_id"]
    #     members = group_data.get("members", [])
    #     if user_id not in members:
    #         print(f"User '{username}' is not a member of group '{group_name}'.")
    #         return

    #     remove_user_from_group(group_name, user_id)
    #     print(f"User '{username}' removed from group '{group_name}'.")

    @requires_admin
    def do_list_users(self, arg):
        """
        Usage: list_users
        """
        print("Users:")
        admin = get_admin_record()
        if not admin:
            return

        keys = getattr(admin, "user_keys", {}) or {}
        for uname in keys:
            user = load_user(uname)
            if user is None:
                continue
            print(f" - {user.get('username')}")

    def do_exit(self, arg):
        return True


if __name__ == "__main__":
    SecureFS().cmdloop()
