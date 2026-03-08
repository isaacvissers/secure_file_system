import cmd

from backend.auth import *
from backend.auth import FILES_DIR
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
        if arg.strip():
            directory_name = arg.strip()
        else:
            directory_name = prompt_required_text("directory name")
        if directory_name is None:
            print("Error: Directory name is required.")
            return

        if not self.current_working_directory.is_relative_to(
            FILES_DIR / self.current_user["username"]
        ):
            print("Error: Cannot create directories outside of your home directory.")
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

        if not self.current_working_directory.is_relative_to(
            FILES_DIR / self.current_user["username"]
        ):
            print("Error: Cannot create files outside of your home directory.")
            return

        try:
            file = File.create(self.current_working_directory, file_name)
            print(f"File '{file_name}' created.")
        except FileExistsError as e:
            print(f"Error: {e}")

    @requires_login
    def do_cd(self, arg):
        """
        Usage: cd <directory_name>
        """
        if arg.strip():
            directory_name = arg.strip()
        else:
            # go to users home directory if no argument provided
            self.current_working_directory = FILES_DIR / self.current_user["username"]
            self._update_prompt()
            return
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

    @requires_login
    def do_ls(self, arg):
        """
        Usage: ls
        """
        entries = list(self.current_working_directory.iterdir())
        dir_names = {e.name for e in entries if e.is_dir()}
        for entry in entries:
            if entry.is_dir():
                print(f"{entry.name}/")
            elif entry.suffix == ".json" and entry.stem in dir_names:
                continue
            else:
                print(entry.name.replace(".json", "", 1))

    @requires_login
    def do_pwd(self, arg):
        """
        Usage: pwd
        """
        if (
            self.current_working_directory
            and self.current_working_directory.is_relative_to(FILES_DIR)
        ):
            relative_path = self.current_working_directory.relative_to(FILES_DIR)
            pwd_str = f"SFS/{relative_path} "
        else:
            pwd_str = "SFS"

        print(pwd_str)

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

        members = group_data.get("members", {})
        if username not in members:
            print(f"User '{username}' is not a member of group '{group_name}'.")
            return

        removed = remove_user_from_group(group_name, username)
        if not removed:
            print(f"Failed to remove user '{username}' from group '{group_name}'.")
            return

        print(f"User '{username}' removed from group '{group_name}'.")

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
