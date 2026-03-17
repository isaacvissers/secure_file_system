import cmd
import hashlib
import json
import shlex
from pathlib import Path

# from backend.auth import *
from backend.auth import (
    FILES_DIR,
    add_user_to_admin,
    create_user_directory,
    requires_admin,
    requires_logged_out,
    requires_login,
)

# from backend.cryptography_utils import *
# from backend.file_utils import *
from backend.file_utils import (
    add_file_to_group,
    check_user_file_integrities,
    remove_file_tracking_for_user,
    try_decrypt_directory,
    try_decrypt_file,
)
from backend.group_utils import add_group_to_user, add_user_to_group
from cli_utils import *
from models.directory import Directory
from models.file import File, Permission
from models.group import Group
from models.user import ADMIN, USERS_DIR, AdminUser, User


class SecureFS(cmd.Cmd):
    def __init__(self):
        super().__init__()
        self.current_user = None
        self.current_working_directory = None
        self._update_prompt()

    def _resolve_directory_display_name(
        self,
        parent_dir,
        encrypted_dir_name: str,
        show_decrypt_error: bool = False,
    ) -> str:
        """Return a decrypted directory name when metadata can be read, else fallback."""
        metadata_path = parent_dir / f".{encrypted_dir_name}"
        if not metadata_path.exists() or not self.current_user:
            return encrypted_dir_name

        file_key_hex = self.current_user.file_keys.get(str(metadata_path))
        decrypted_dir = try_decrypt_directory(metadata_path, file_key_hex)
        if decrypted_dir:
            return decrypted_dir.file_name.lstrip(".")

        if show_decrypt_error:
            print(
                f"Error decrypting metadata for {metadata_path}, displaying encrypted name."
            )
        return encrypted_dir_name

    def _build_displayed_path(self):
        """Return cwd path under FILES_DIR with decrypted names when available."""
        if not (
            self.current_working_directory
            and self.current_working_directory.is_relative_to(FILES_DIR)
        ):
            return None

        relative_path = self.current_working_directory.relative_to(FILES_DIR)
        base_dir = FILES_DIR
        displayed_path = ""

        for part in relative_path.parts:
            displayed_part = self._resolve_directory_display_name(base_dir, part)
            displayed_path += f"/{displayed_part}"

            base_dir = base_dir / part

        return displayed_path

    def _update_prompt(self):
        """Update the interactive prompt to include the logged-in username."""
        displayed_path = self._build_displayed_path()
        if displayed_path is not None:
            self.prompt = f"SFS{displayed_path}> "
        else:
            self.prompt = "SFS> "

    def _refresh_current_user(self, file_key_updates=None) -> None:
        """Reload current user data from storage while preserving session state."""
        if not self.current_user:
            return
        username = self.current_user.username
        if not username:
            return
        current_user = self.current_user
        if file_key_updates:
            self.current_user.file_keys.update(file_key_updates)

        refreshed_user, _ = User.get_user(self.current_user.path, self.current_user_key)
        if refreshed_user is None:
            self.current_user = current_user
            return

        merged_file_keys = refreshed_user.file_keys.copy()
        merged_file_keys.update(self.current_user.file_keys)

        refreshed_user.file_keys = merged_file_keys
        self.current_user = refreshed_user

    @requires_logged_out
    def do_login(self, arg):
        """
        Usage: login
        """
        credentials = prompt_credentials()
        if credentials is None:
            return
        username, password = credentials

        encrypted_name = hashlib.sha256(username.encode("utf-8")).hexdigest()
        user_file_path = USERS_DIR / encrypted_name

        if not user_file_path.exists():
            print(f"Error: User '{username}' does not exist.")
            return

        if username == ADMIN:
            user, user_key = AdminUser.get_user(user_file_path)
        else:
            user, user_key = User.get_user(user_file_path)

        if not user:
            print("Error: Could not load user record.")
            return

        if not user.verify_password(password):
            print("Error: Incorrect password.")
            return

        self.current_user = user
        self.current_user_key = user_key

        # set working directory to the user's files directory
        self.current_working_directory = (
            FILES_DIR / hashlib.sha256(username.encode("utf-8")).hexdigest()
        )

        # Check owned files recursively for offline tampering.
        compromised_paths = []
        if self.current_working_directory.exists():
            compromised_paths = check_user_file_integrities(
                self.current_user,
                self.current_working_directory,
            )
        if compromised_paths:
            print("Warning: The following files may have been compromised:")
            print()
            for path in compromised_paths:
                print(f"- {path}")

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
            / hashlib.sha256(self.current_user.username.encode("utf-8")).hexdigest()
        ):
            print("Error: Cannot create directories outside of your home directory.")
            return

        try:
            Directory.create(
                self.current_working_directory, directory_name, self.current_user
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
            / hashlib.sha256(self.current_user.username.encode("utf-8")).hexdigest()
        ):
            print("Error: Cannot create files outside of your home directory.")
            return

        try:
            file = File.create(
                self.current_working_directory, file_name, self.current_user
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
                / hashlib.sha256(self.current_user.username.encode("utf-8")).hexdigest()
            )
            self._update_prompt()
            return
        if directory_name in {".", "./"}:
            return
        elif directory_name in {"..", "../"}:
            parent_dir = self.current_working_directory.parent
            if parent_dir.is_relative_to(FILES_DIR) or parent_dir == (FILES_DIR):
                self.current_working_directory = parent_dir
                self._update_prompt()
            else:
                print("Error: Access outside of storage is not allowed.")
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
                metadata_path = self.current_working_directory / f".{entry.name}"
                if metadata_path.exists():
                    display_name = self._resolve_directory_display_name(
                        self.current_working_directory,
                        entry.name,
                        show_decrypt_error=True,
                    )
                    print(f"{display_name}/")
            elif entry.stem.startswith(".") and entry.stem[1:] in dir_names:
                continue
            else:
                file_key_hex = self.current_user.file_keys.get(str(entry))
                decrypted_file = try_decrypt_file(entry, file_key_hex)
                if decrypted_file:
                    print(decrypted_file.file_name)
                else:
                    print(f"Error decrypting file {entry}, displaying encrypted name.")
                    print(entry.name)

    @requires_login
    def do_pwd(self, arg):
        """
        Usage: pwd
        """
        displayed_path = self._build_displayed_path()
        pwd_str = f"SFS{displayed_path}" if displayed_path is not None else "SFS"

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
            file_key_hex = self.current_user.file_keys.get(str(file_path))
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
                    self.current_user,
                    body=output,
                )
                self._refresh_current_user(
                    {str(file.path): file.encrypted_file_key.hex()}
                )
            else:
                file = File.get_file(
                    file_path,
                    bytes.fromhex(self.current_user.file_keys.get(str(file_path))),
                )
                file.body = file.body + output if append_mode else output
                file.save()
                self._refresh_current_user()

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
        file_key = bytes.fromhex(self.current_user.file_keys.get(str(source_path)))
        file = File.get_file(source_path, file_key)
        file.rename_file(self.current_user, dest_name)
        remove_file_tracking_for_user(self.current_user, source_path)
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
                / hashlib.sha256(self.current_user.username.encode("utf-8")).hexdigest()
            )
            and not file_path
            == FILES_DIR
            / hashlib.sha256(self.current_user.username.encode("utf-8")).hexdigest()
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
            file_key = bytes.fromhex(self.current_user.file_keys.get(str(target_path)))
            file = File.get_file(target_path, file_key)
            file.permission = Permission(permissions)
            file.save()
            if permissions == Permission.GROUP.value:
                file_key = file.encrypted_file_key
                for group_name, group_info in self.current_user.group_keys.items():

                    if group_name.lower() == "all":
                        continue

                    group_key = bytes.fromhex(group_info["key"])
                    group_id = group_info["id"]

                    group_obj = Group.get_group(Path(group_id), group_key)

                    if group_obj:
                        add_file_to_group(group_obj, group_key, file, file_key)
                    else:
                        print(f"Error: Could not access group record for {group_name}")

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
                / f".{hashlib.sha256(file_name.encode('utf-8')).hexdigest()}"
            )
            if not metadata_path.exists():
                print(f"Error: Metadata for directory '{file_name}' does not exist.")
                return
            file_path = metadata_path
        if not file_path.is_file():
            print(f"Error: '{file_name}' is not a valid file.")
            return
        try:
            file_key = bytes.fromhex(self.current_user.file_keys.get(str(file_path)))
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

        encrypted_name = hashlib.sha256(username.encode()).hexdigest()
        if (USERS_DIR / encrypted_name).exists():
            print(f"Error: User '{username}' already exists.")
            return

        created_user, master_key = User.create(username, password)
        if created_user is None:
            print("Error: Username already exists.")
            return

        add_user_to_admin(self.current_user, created_user, master_key)

        all_group_info = self.current_user.group_keys.get("all")

        create_user_directory(created_user)

        if all_group_info:
            group_path = Path(all_group_info["id"])
            group_key = bytes.fromhex(all_group_info["key"])
            all_group_obj = Group.get_group(group_path, group_key)

            if all_group_obj:
                add_user_to_group(created_user, all_group_obj)
                add_group_to_user(created_user, all_group_obj, all_group_info["key"])
        else:
            print(f"Warning: Group 'all' not found.")

        print(f"User created: {username} ")

    @requires_admin
    def do_create_group(self, arg):
        """
        Usage: create_group
        """
        group_name = prompt_required_text("group name")
        if group_name is None:
            return

        if group_name in self.current_user.group_keys:
            print(f"Error: Group '{group_name}' already exists.")
            return

        group, group_master_key = Group.create(group_name)
        add_group_to_user(self.current_user, group, group_master_key)

        print(f"Group created: {group_name}")

    @requires_admin
    def do_add_user_to_group(self, arg):
        group_name = prompt_required_text("group name")
        username = prompt_required_text("username")
        if not group_name or not username:
            return

        group_info = self.current_user.group_keys.get(group_name)
        user_metadata = self.current_user.user_keys.get(username)

        if not group_info or not user_metadata:
            print("Error: Missing group or user metadata.")
            return

        group_obj = Group.get_group(
            Path(group_info["id"]), bytes.fromhex(group_info["key"])
        )

        user_path = USERS_DIR / user_metadata["id"]
        user_key = bytes.fromhex(user_metadata["key"])
        target_user = self.current_user.get_user(user_path, user_key)

        if not group_obj or not target_user:
            print("Error: Could not load the records.")
            return

        add_user_to_group(target_user[0], group_obj)
        add_group_to_user(target_user[0], group_obj, group_info["key"])

        print(f"Success: {username} added to {group_name}.")

    @requires_admin
    def do_remove_user_from_group(self, arg):
        """Usage: remove_user_from_group"""
        group_name = prompt_required_text("group name")
        if not group_name:
            return

        username = prompt_required_text("username")
        if not username:
            return

        group_info = self.current_user.group_keys.get(group_name)
        user_metadata = self.current_user.user_keys.get(username)

        if not group_info:
            print(f"Error: Group '{group_name}' does not exist.")
            return
        if not user_metadata:
            print(f"Error: User '{username}' does not exist.")
            return

        user_file_path = USERS_DIR / user_metadata["id"]
        user_key_bytes = bytes.fromhex(user_metadata["key"])
        target_user = self.current_user.get_user(user_file_path, user_key_bytes)

        if target_user:
            if group_name in target_user.group_keys:
                del target_user.group_keys[group_name]
                target_user.save()
            else:
                print(f"Warning: Group '{group_name}' wasn't in {username}'s key list.")
        else:
            print(f"Error: Could not access record for user '{username}'.")
            return

        group_path = Path(group_info["id"])
        group_key = bytes.fromhex(group_info["key"])
        group_obj = Group.get_group(group_path, group_key)

        if username in group_obj.members:
            del group_obj.members[username]
            group_obj.save(group_key)
            print(f"User '{username}' successfully removed from group '{group_name}'.")
        else:
            print(f"User '{username}' was not a member of group '{group_name}'.")

    def do_exit(self, arg):
        return True


if __name__ == "__main__":
    SecureFS().cmdloop()
