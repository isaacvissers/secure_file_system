from pathlib import Path


def flip_last_hash_nibble(path: Path) -> tuple[str, str]:
    """Flip only the final hash hex nibble in an encrypted file blob.

    File format is: nonce + ciphertext + 64-byte ASCII hex integrity hash.
    This helper preserves file size and ciphertext bytes, mutating only the
    last hash character so decryption should still succeed while integrity fails.
    """
    content = path.read_bytes()
    if len(content) < 64:
        raise ValueError("File too short to contain integrity hash")

    hash_bytes = bytearray(content[-64:])
    last = chr(hash_bytes[-1]).lower()
    if last not in "0123456789abcdef":
        raise ValueError("Trailing hash is not valid lowercase hex")

    replacement = "f" if last != "f" else "e"
    hash_bytes[-1] = ord(replacement)

    path.write_bytes(content[:-64] + bytes(hash_bytes))
    return last, replacement


def flip_last_gcm_tag_nibble(path: Path) -> tuple[str, str]:
    """Flip only the final nibble of the GCM tag inside an encrypted file blob.

    Layout is: nonce(12) + ciphertext + tag(16) + hash(64). Mutating a tag nibble
    preserves file size and ciphertext bytes, but authenticated decrypt raises
    InvalidTag. This is useful for testing best-effort, unverified name recovery.
    """
    content = path.read_bytes()
    if len(content) < (12 + 16 + 64):
        raise ValueError("File too short to contain nonce/tag/hash segments")

    tag_bytes = bytearray(content[-80:-64])
    last = chr(tag_bytes[-1]).lower()
    replacement = "f" if last != "f" else "e"
    tag_bytes[-1] = ord(replacement)

    path.write_bytes(content[:-80] + bytes(tag_bytes) + content[-64:])
    return last, replacement
