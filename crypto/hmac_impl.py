"""
HMAC (Hash-based Message Authentication Code) implemented from scratch.
Uses our from-scratch SHA-256 implementation.
RFC 2104 compliant.
"""

from .sha256 import sha256

BLOCK_SIZE = 64  # SHA-256 block size in bytes


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA256.
    key     : secret key (bytes)
    message : data to authenticate (bytes)
    Returns : 32-byte MAC tag
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Keys longer than block size are hashed
    if len(key) > BLOCK_SIZE:
        key = sha256(key)

    # Keys shorter than block size are zero-padded
    key = key + b'\x00' * (BLOCK_SIZE - len(key))

    # Inner and outer padding
    i_pad = bytes(b ^ 0x36 for b in key)
    o_pad = bytes(b ^ 0x5C for b in key)

    inner = sha256(i_pad + message)
    outer = sha256(o_pad + inner)
    return outer


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    return hmac_sha256(key, message).hex()


def verify_hmac(key: bytes, message: bytes, tag: bytes) -> bool:
    """Constant-time HMAC verification to prevent timing attacks."""
    expected = hmac_sha256(key, message)
    if len(expected) != len(tag):
        return False
    result = 0
    for a, b in zip(expected, tag):
        result |= a ^ b
    return result == 0
