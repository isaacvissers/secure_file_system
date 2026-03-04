import cmd

from backend.auth import *
from backend.auth import FILES_DIR, _iter_user_records
from backend.cryptography_utils import *
from backend.group_utils import *
from cli_utils import *
from models.directory import Directory
from models.file import File


class SecureFS(cmd.Cmd):
    def __init__(self):
        super().__init__()
        self.current_user = None
        self.current_working_directory = None
        self._update_prompt()

    def _update_prompt(self):
        """Update the interactive prompt to include the logged-in username."""
        if (
            self.current_working_directory
            and self.current_working_directory.is_relative_to(FILES_DIR)
        ):
            relative_path = self.current_working_directory.relative_to(FILES_DIR)
            self.prompt = f"SFS/{relative_path}> "
        else:
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
        self.current_working_directory = FILES_DIR / user_data["username"]
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
        if arg.strip():
            directory_name = arg.strip()
        else:
            directory_name = prompt_required_text("directory name")
        if directory_name is None:
            print("Error: Directory name is required.")
            return

        try:
            directory = Directory.create(self.current_working_directory, directory_name)
            print(f"Directory '{directory_name}' created.")
        except FileExistsError as e:
            print(f"Error: {e}")

    @requires_login
    def do_touch(self, arg):
        """
        Usage: touch <file_name>
        """
        if arg.strip():
            file_name = arg.strip()
        else:
            file_name = prompt_required_text("file name")
        if file_name is None:
            print("Error: File name is required.")
            return

        try:
            file = File.create(self.current_working_directory, file_name)
            print(f"File '{file_name}' created.")
        except FileExistsError as e:
            print(f"Error: {e}")

    def do_cd(self, arg):
        """
        Usage: cd <directory_name>
        """
        if arg.strip():
            directory_name = arg.strip()
        else:
            directory_name = prompt_required_text("directory name")
        if directory_name is None:
            print("Error: Directory name is required.")
            return

        new_path = (self.current_working_directory / directory_name).resolve()
        if not new_path.is_relative_to(FILES_DIR.resolve()):
            print("Error: Access outside of storage is not allowed.")
            return
        if not new_path.is_dir():
            print(f"Error: '{directory_name}' is not a valid directory.")
            return

        self.current_working_directory = new_path
        self._update_prompt()

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
