import os

from src.cryptography_utils import hash_password, verify_password


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
