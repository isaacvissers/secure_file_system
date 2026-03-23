# The Farmer SFS

## Deployment Instructions / Setup

Our project uses Github Actions for CI/CD with a clear split on every push. Our CI ensures code quality on every push by running all of our unit/integration tests, and running a linter. All new versions are tagged using semantic versioning [1] (for example v1.0.0). When a tag is pushed our CD builds native binaries for Linux, macOS and windows and publishes them as a GitHub release where they can be downloaded as individual artifacts. This is continuous delivery (automated packaging and release) but not automatic deployment (as installation and setup is still a manual process). 

If a user wants to use our file system they need to go to github releases for our project and install the latest prebuilt binaries for their OS. There are 2 binaries needed: secure-fs-admin-setup-<os>-vx.x.x.<ext> and secure-fs-<os>-vx.x.x.<ext>. After downloading, the user should run the admin setup binary. This will create an admin with the credentials (admin/admin) and the required file system structure setup. From the same parent directory the user can then run the main secure file system binary in order to access the system. All required system documents will be created in a storage/subdirectory. So the binaries should be run in a writable folder.

## User Guide

- Go to the github releases pages https://github.com/isaacvissers/secure_file_system/releases
- Download the 2 binaries for your OS
  - secure-fs-<OS>-x86_64-vX.X.X.<extension>
  - secure-fs-admin-setup-<OS>-x86_64-vX.X.X.<extension>
- Unzip both folders and place the binary executables in the same directory. It must be a writable directory
- Run the admin setup, which creates an admin user with the credentials (user: admin, pass: admin). This admin user can be used to create and manage users and groups
- Run the main program. It will launch a CLI to use the program. The CLI Provides the following commands:
    - Available to all users
      - help
        - Print all available commands
      - login
        - Authenticate the user or admin in with username and password
      - logout
        - Log the current user out
      - exit
        - Close the application
    - Admin Only
      - create_user
        - create a new user with specified username and password
        - This will also create a home directory for the user and add the user to the all group
      - create_group
        - Create a new group
      - add_user_to_group
        - add specified user to the specified group
        - This will also add any of that users files with group permissions to that group
      - remove_user_from_group
        - Remove specified user from the specified group
        - This will also remove the users files from that group
    - User Only
      - cat <file_name>
          - Print the contents of <file_name> as plaintext if you have access to the file
      - cd <directory_name>
        - Traverse into <directory_name>
        - This command only supports relative paths
        - cd .. can be used to return to the parent directory
        - cd can be used to return to the user’s home directory
        - We only support traversing into a directory you have access to
      - Echo
          - echo “TEXT” > <file_name>
            - Sets the contents of <file_name> to TEXT
            - If <file_name> doesn’t exist in the current working directory it will be created
          - echo “TEXT” >> filename
              - Appends “TEXT” to the end of the contents of <file_name>
              - If <file_name> doesn’t exist in the current working directory it will be created
        - get_permissions <name>
          - Prints the permissions of file or directory <name>
        - ls
          - Print the contents of the current working directory
          - This will include encrypted file/directory  names if you do not have access, and real decrypted names for files/directories you have access to
        - mkdir <directory_name>
          - Creates a subdirectory named <directory_name> in the current working directory
          - We only support creating files within the user’s home directory
          - Directories are created with default permissions of user
        - mv <file_name> <new_name>
            - Rename <file_name> to <new_name>
            - We only support renaming files, not directories
            - We only support renaming files you are the owner of (within your home directory)
        - pwd
          - Prints the current working directory
        - set_permissions <name> <permission>
          - Set permissions of file or directory <name> to <permission>
          - We only support setting the permissions of files you are the owner of (within your home directory)
        - touch <file_name>
          - Creates <file_name> in the current working directory
          - We only support creating files within the user’s home directory
          - Files are created with default permissions of user

