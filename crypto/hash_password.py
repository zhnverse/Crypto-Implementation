"""
Password Hashing and Salting — implemented from scratch.
Uses our from-scratch SHA-256.
Applies PBKDF2-like key stretching using iterated HMAC.
"""

import os
import struct
from .sha256 import sha256
from .hmac_impl import hmac_sha256

SALT_SIZE = 32       # 256-bit salt
ITERATIONS = 10000   # stretch iterations
KEY_LEN = 32         # desired output length (256-bit)


def generate_salt() -> bytes:
    """Generate a cryptographically random 32-byte salt using OS entropy."""
    return os.urandom(SALT_SIZE)


def _pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, key_len: int) -> bytes:
    """
    Minimal PBKDF2 using HMAC-SHA256, implemented from scratch.
    Produces key_len bytes of derived key material.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')

    num_blocks = (key_len + 31) // 32  # SHA-256 outputs 32 bytes per block
    derived = b''

    for block_num in range(1, num_blocks + 1):
        # U1 = PRF(password, salt || INT(i))
        block_index = struct.pack('>I', block_num)
        u = hmac_sha256(password, salt + block_index)
        result = bytearray(u)

        for _ in range(1, iterations):
            u = hmac_sha256(password, u)
            for j in range(len(result)):
                result[j] ^= u[j]

        derived += bytes(result)

    return derived[:key_len]


def hash_password(password: str, salt: bytes = None):
    """
    Hash a password with a fresh random salt.
    Returns (hash_hex, salt_hex)
    """
    if salt is None:
        salt = generate_salt()
    digest = _pbkdf2_sha256(password.encode('utf-8'), salt, ITERATIONS, KEY_LEN)
    return digest.hex(), salt.hex()


def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    """Verify a password against its stored hash and salt."""
    salt = bytes.fromhex(salt_hex)
    new_hash, _ = hash_password(password, salt)
    # Constant-time comparison
    if len(new_hash) != len(stored_hash_hex):
        return False
    result = 0
    for a, b in zip(new_hash, stored_hash_hex):
        result |= ord(a) ^ ord(b)
    return result == 0
