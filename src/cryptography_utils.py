from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def hash_password(password: bytes, salt: bytes):
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
