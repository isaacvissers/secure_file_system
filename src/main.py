import cmd
import hashlib
import json
import shlex

from backend.auth import *
from backend.auth import FILES_DIR
from backend.cryptography_utils import *
from backend.file_utils import *
from backend.file_utils import add_file_to_group
from backend.group_utils import *
from backend.group_utils import get_user_groups_by_username
from cli_utils import *
from models.directory import Directory
from models.file import File, Permission


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

            # loop through the rest of the path and replace directory names with their decrypted names if possible
            base_dir = FILES_DIR
            displayed_path = ""
            for part in relative_path.parts:
                metadata_path = base_dir / f".{part}"
                if metadata_path.exists():
                    try:
                        file_key_hex = self.current_user["file_keys"].get(
                            str(metadata_path)
                        )
                        if file_key_hex:
                            file_key = bytes.fromhex(file_key_hex)
                            metadata_file = File.get_file(metadata_path, file_key)
                            decrypted_name = metadata_file.file_name.lstrip(".")
                            base_dir = base_dir / part
                            displayed_path += f"/{decrypted_name}"
                    except Exception:
                        print(
                            f"Error decrypting metadata for {metadata_path}, using encrypted name in prompt."
                        )
                        base_dir = base_dir / part
                        displayed_path += f"/{part}"
                else:
                    print(
                        f"Metadata for {base_dir / part} not found, using encrypted name in prompt."
                    )
                    base_dir = base_dir / part
                    displayed_path += f"/{part}"

            self.prompt = f"SFS{displayed_path}> "
        else:
            self.prompt = "SFS> "

    def _refresh_current_user(self, file_key_updates=None) -> None:
        """Reload current user data from storage while preserving session state."""
        if not self.current_user:
            return
        username = self.current_user.get("username")
        if not username:
            return
        current_user = dict(self.current_user)
        if file_key_updates:
            current_user.setdefault("file_keys", {}).update(file_key_updates)

        refreshed_user = load_user(username)
        if refreshed_user is None:
            self.current_user = current_user
            return

        merged_user = {**current_user, **refreshed_user}
        merged_user["file_keys"] = {
            **current_user.get("file_keys", {}),
            **refreshed_user.get("file_keys", {}),
        }
        self.current_user = merged_user

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
            self.current_working_directory = (
                FILES_DIR / hashlib.sha256(username.encode("utf-8")).hexdigest()
            )
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
            self.current_working_directory = (
                FILES_DIR / hashlib.sha256(username.encode("utf-8")).hexdigest()
            )

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

        # TODO this check should be handled in the Directory.create method instead to ensure all directory creation is safe, not just creation through the CLI
        if not self.current_working_directory.is_relative_to(
            FILES_DIR
            / hashlib.sha256(self.current_user["username"].encode("utf-8")).hexdigest()
        ):
            print("Error: Cannot create directories outside of your home directory.")
            return

        try:
            Directory.create(
                self.current_working_directory,
                directory_name,
                self.current_user["username"],
            )
            self._refresh_current_user()

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
            FILES_DIR
            / hashlib.sha256(self.current_user["username"].encode("utf-8")).hexdigest()
        ):
            print("Error: Cannot create files outside of your home directory.")
            return

        try:
            file = File.create(
                self.current_working_directory, file_name, self.current_user["username"]
            )
            self._refresh_current_user({str(file.path): file.encrypted_file_key.hex()})
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
            self.current_working_directory = (
                FILES_DIR
                / hashlib.sha256(
                    self.current_user["username"].encode("utf-8")
                ).hexdigest()
            )
            self._update_prompt()
            return
        if directory_name is None:
            print("Error: Directory name is required.")
            return

        new_path = (
            self.current_working_directory
            / hashlib.sha256(directory_name.encode("utf-8")).hexdigest()
        ).resolve()
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
            elif entry.stem.startswith(".") and entry.stem[1:] in dir_names:
                continue
            else:
                print(entry.name)

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

    @requires_login
    def do_cat(self, arg):
        """
        Usage: cat <file_name>
        """
        if not arg.strip():
            print("Error: File name is required.")
            return

        file_name = arg.strip()
        file_path = (
            self.current_working_directory
            / hashlib.sha256(file_name.encode("utf-8")).hexdigest()
        )

        if not file_path.is_file():
            print(f"Error: '{arg.strip()}' is not a valid file.")
            return

        # TODO: ensure user has permission to read the file
        try:
            file_key_hex = self.current_user["file_keys"].get(str(file_path))
            file_key = bytes.fromhex(file_key_hex)
            file = File.get_file(file_path, file_key)
            print(file.body)
        except Exception as e:
            print(f"Error reading file: {e}")

    @requires_login
    def do_echo(self, arg):
        """
        Usage:
          echo [-n] <content>
          echo [-n] <content> > <file_name>
          echo [-n] <content> >> <file_name>
        """
        # TODO: ensure user has permission to write to file

        try:
            lexer = shlex.shlex(arg, posix=True, punctuation_chars=">")
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except ValueError as e:
            print(f"Error: {e}")
            return

        suppress_newline = False
        if tokens and tokens[0] == "-n":
            suppress_newline = True
            tokens = tokens[1:]

        redirect_index = None
        redirect_op = None
        for idx, token in enumerate(tokens):
            if token in {">", ">>"}:
                redirect_index = idx
                redirect_op = token
                break

        if redirect_index is None:
            output = " ".join(tokens)
            print(output, end="" if suppress_newline else "\n")
            return

        content_tokens = tokens[:redirect_index]
        target_tokens = tokens[redirect_index + 1 :]

        if len(target_tokens) != 1:
            print(
                "Error: Invalid syntax. Usage: echo [-n] <content> [> | >>] <file_name>"
            )
            return

        file_name = target_tokens[0].strip()
        if not file_name:
            print("Error: File name is required.")
            return

        file_path = (
            self.current_working_directory
            / hashlib.sha256(file_name.encode("utf-8")).hexdigest()
        )
        content = " ".join(content_tokens)
        output = content if suppress_newline else content + "\n"
        append_mode = redirect_op == ">>"

        try:
            # TODO: decrypt body contents first, modify the decrypted content, then re-encrypt and write back to file instead of just writing raw output
            if not file_path.exists():
                # TODO I think we need to rethink this part too
                logical_name = file_name
                file = File.create(
                    self.current_working_directory,
                    logical_name,
                    self.current_user["username"],
                    body=output,
                )
                self._refresh_current_user(
                    {str(file.path): file.encrypted_file_key.hex()}
                )
            else:
                file = File.get_file(
                    file_path,
                    bytes.fromhex(self.current_user["file_keys"].get(str(file_path))),
                )
                file.body = file.body + output if append_mode else output
                file.save()

        except Exception as e:
            print(f"Error writing to file: {e}")

    @requires_login
    def do_mv(self, arg):
        """
        Usage: mv <source> <destination>
        """
        tokens = shlex.split(arg)
        if len(tokens) != 2:
            print("Error: Invalid syntax. Usage: mv <source> <destination>")
            return

        # rename the file, must be within same directory
        source_name, dest_name = tokens
        source_path = (
            self.current_working_directory
            / hashlib.sha256(source_name.encode("utf-8")).hexdigest()
        )
        dest_path = (
            self.current_working_directory
            / hashlib.sha256(dest_name.encode("utf-8")).hexdigest()
        )

        if not source_path.is_file():
            print(f"Error: Source file '{source_name}' does not exist.")
            return
        if dest_path.exists():
            print(f"Error: Destination file '{dest_name}' already exists.")
            return
        file_key = bytes.fromhex(self.current_user["file_keys"].get(str(source_path)))
        file = File.get_file(source_path, file_key)
        file.rename_file(dest_name)
        self._refresh_current_user()

    @requires_login
    def do_set_permissions(self, arg):
        """
        Usage: set_permissions <file_name> <permissions> [-r]
        Permissions format: 'user', 'group', or 'all'
        """
        tokens = shlex.split(arg)
        if len(tokens) not in {2, 3}:
            print(
                "Error: Invalid syntax. Usage: set_permissions <file_name> <permissions> [-r]"
            )
            return

        recursive = False
        if len(tokens) == 3:
            if tokens[2] != "-r":
                print(
                    "Error: Invalid syntax. Usage: set_permissions <file_name> <permissions> [-r]"
                )
                return
            recursive = True

        file_name, permissions = tokens[:2]

        file_name = file_name.rstrip("/")

        file_path = (
            self.current_working_directory
            / hashlib.sha256(file_name.encode("utf-8")).hexdigest()
        )

        if not file_path.exists():
            print(f"Error: File or directory '{file_name}' does not exist.")
            return

        if (
            not file_path.is_relative_to(
                FILES_DIR
                / hashlib.sha256(
                    self.current_user["username"].encode("utf-8")
                ).hexdigest()
            )
            and not file_path
            == FILES_DIR
            / hashlib.sha256(self.current_user["username"].encode("utf-8")).hexdigest()
        ):
            print("Error: You are not the owner of this file.")
            return

        if permissions not in {perm.value for perm in Permission}:
            print(
                "Error: Invalid permissions format. permissions values are 'user', 'group', or 'all'."
            )
            return

        target_paths = []

        if not file_path.is_dir():
            target_paths.append(file_path)
        else:
            metadata_path = file_path.parent / f".{file_path.name}"
            target_paths.append(metadata_path)
            if recursive:
                # Add all files in the directory tree, including metadata dotfiles
                # for nested directories.
                for nested_path in file_path.rglob("*"):
                    target_paths.append(nested_path)
                    if nested_path.is_dir():
                        target_paths.append(nested_path.parent / f".{nested_path.name}")

        target_paths = list(dict.fromkeys(target_paths))

        for target_path in target_paths:
            if target_path.is_dir():
                continue
            file_key = bytes.fromhex(
                self.current_user["file_keys"].get(str(target_path))
            )
            file = File.get_file(target_path, file_key)
            file.permission = Permission(permissions)
            file.save()
            if permissions == Permission.GROUP.value:
                file_key = file.encrypted_file_key
                for g in get_user_groups_by_username(self.current_user["username"]):
                    add_file_to_group(g, file_key)

    @requires_login
    def do_get_permissions(self, arg):
        """
        Usage: get_permissions <file_name>
        """
        if not arg.strip():
            print("Error: File name is required.")
            return

        file_name = arg.strip()
        file_path = (
            self.current_working_directory
            / hashlib.sha256(file_name.encode("utf-8")).hexdigest()
        )

        if file_path.is_dir():
            metadata_path = (
                self.current_working_directory
                / hashlib.sha256(f".{file_name}".encode("utf-8")).hexdigest()
            )
            if not metadata_path.exists():
                print(f"Error: Metadata for directory '{file_name}' does not exist.")
                return
            file_path = metadata_path

        if not file_path.is_file():
            print(f"Error: '{file_name}' is not a valid file.")
            return

        try:
            file_key = bytes.fromhex(self.current_user["file_keys"].get(str(file_path)))
            file = File.get_file(file_path, file_key)
            print(file.permission.value)
        except Exception as e:
            print(f"Error reading file: {e}")

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
