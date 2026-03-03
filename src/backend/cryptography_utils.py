from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

## ----------------
## Password Hashing
## ----------------
def hash_password(password: bytes, salt: bytes):
    '''
    Hash the password using Argon2id and return the hash bytes.
    '''
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
    '''
    Verify the password attempt against the stored hash.
    Returns True if the password is correct, False otherwise.
    '''
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

## ----------------
## RSA Key Generation
## ----------------
def generate_rsa_keys():
    """
    Generate an RSA key pair (private + public) and return serialized bytes.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_bytes, public_bytes

def encrypt_private_key(private_bytes: bytes, salt: bytes, password: bytes):
    """
    Encrypt the RSA private key using AES-GCM with a key derived from the password.
    Returns (encrypted_private_key, nonce, salt)
    """
    key = hash_password(password, salt)

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_private_key = aesgcm.encrypt(nonce, private_bytes, associated_data=None)

    return encrypted_private_key, nonce

def decrypt_private_key(user_dict: dict, password: str) -> rsa.RSAPrivateKey:
    """
    Decrypt the RSA private key for a user using their password.
    
    Args:
        user_dict: The user metadata dict (must include 'private_key', 'private_key_nonce', 'salt')
        password: The user's password
    
    """
    salt = bytes.fromhex(user_dict["salt"])
    key = hash_password(password.encode(), salt)
    encrypted_private_key = bytes.fromhex(user_dict["encrypted_private_key"])
    nonce = bytes.fromhex(user_dict["private_key_nonce"])
    aesgcm = AESGCM(key)
    private_bytes = aesgcm.decrypt(nonce, encrypted_private_key, associated_data=None)
    
    private_key = serialization.load_pem_private_key(
        private_bytes,
        password=None
    )
    
    return private_key
