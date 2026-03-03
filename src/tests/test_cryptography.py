import os

import pytest
from cryptography.hazmat.primitives import serialization

from backend.cryptography_utils import (
    decrypt_private_key,
    encrypt_private_key,
    generate_rsa_keys,
)


def test_generate_rsa_keys_returns_pem_bytes():
    private_bytes, public_bytes = generate_rsa_keys()
    assert isinstance(private_bytes, (bytes, bytearray))
    assert isinstance(public_bytes, (bytes, bytearray))
    # PEM files begin with these headers
    assert private_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert public_bytes.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_encrypt_decrypt_private_key_round_trip():
    private_bytes, public_bytes = generate_rsa_keys()
    password = "s3cret-pass"
    salt = os.urandom(16)

    encrypted, nonce = encrypt_private_key(private_bytes, salt, password.encode())
    assert isinstance(encrypted, (bytes, bytearray))
    assert isinstance(nonce, (bytes, bytearray))

    user_dict = {
        "salt": salt.hex(),
        "encrypted_private_key": encrypted.hex(),
        "private_key_nonce": nonce.hex(),
    }

    recovered_priv = decrypt_private_key(user_dict, password)
    # serialize recovered public key and compare to original public bytes
    recovered_pub_bytes = recovered_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert recovered_pub_bytes == public_bytes


def test_decrypt_private_key_fails_with_wrong_password():
    private_bytes, _ = generate_rsa_keys()
    password = "correct"
    salt = os.urandom(16)

    encrypted, nonce = encrypt_private_key(private_bytes, salt, password.encode())
    user_dict = {
        "salt": salt.hex(),
        "encrypted_private_key": encrypted.hex(),
        "private_key_nonce": nonce.hex(),
    }

    with pytest.raises(Exception):
        decrypt_private_key(user_dict, "incorrect")


import os

from backend.cryptography_utils import hash_password, verify_password


def test_hash_password_returns_bytes_with_expected_length():
    password = b"correct horse battery staple"
    salt = os.urandom(16)

    hashed = hash_password(password, salt)

    assert isinstance(hashed, bytes)
    assert len(hashed) == 32


def test_verify_password_returns_true_for_correct_password():
    password = b"super-secret"
    salt = os.urandom(16)
    stored_hash = hash_password(password, salt)

    assert verify_password(password, salt, stored_hash) is True


def test_verify_password_returns_false_for_incorrect_password():
    password = b"super-secret"
    wrong_password = b"definitely-wrong"
    salt = os.urandom(16)
    stored_hash = hash_password(password, salt)

    assert verify_password(wrong_password, salt, stored_hash) is False


def test_verify_password_returns_false_for_wrong_salt():
    password = b"super-secret"
    original_salt = os.urandom(16)
    wrong_salt = os.urandom(16)
    stored_hash = hash_password(password, original_salt)

    assert verify_password(password, wrong_salt, stored_hash) is False
