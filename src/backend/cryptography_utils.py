import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


## ----------------
## Password Hashing
## ----------------
def hash_password(password: bytes, salt: bytes):
    """
    Hash the password using Argon2id and return the hash bytes.
    """
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )
    return kdf.derive(password)


def verify_password(password_attempt: bytes, salt: bytes, stored_hash: bytes):
    """
    Verify the password attempt against the stored hash.
    Returns True if the password is correct, False otherwise.
    """
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )
    try:
        kdf.verify(password_attempt, stored_hash)
        return True
    except:
        return False
