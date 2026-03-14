import os

from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def derive_key_from_password(password: str, salt: bytes, key_length: int = 32) -> bytes:
    argon2 = Argon2id(
        salt=salt,
        length=key_length,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )
    return argon2.derive(password.encode())


def encrypt_with_key(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_with_key(encrypted_data: bytes, key: bytes) -> bytes:
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def verify_password(password: str, salt_hex: str, verifier_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(verifier_hex)
        candidate = derive_key_from_password(password, salt)
    except Exception:
        return False
    return constant_time.bytes_eq(candidate, expected)


def create_password_to_verify(password: str, salt_bytes: int = 16) -> tuple[str, str]:
    salt = os.urandom(salt_bytes)
    verifier = derive_key_from_password(password, salt)
    return salt.hex(), verifier.hex()
