import cmd

from auth import *
from cli_utils import *
from cryptography_utils import *


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

    def do_exit(self, arg):
        return True


if __name__ == "__main__":
    SecureFS().cmdloop()
