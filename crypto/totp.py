"""
TOTP (Time-based One-Time Password) — implemented from scratch.
RFC 6238 / RFC 4226 compliant.
Uses HMAC-SHA1 (implemented here from scratch for TOTP specifically).
"""

import os
import struct
import time
from .sha256 import sha256

# ── SHA-1 from scratch (needed for standard TOTP / RFC 4226) ──────────────────

_SHA1_K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
_SHA1_H0 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
_MASK32 = 0xFFFFFFFF


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _sha1_pad(msg: bytes) -> bytes:
    bit_len = len(msg) * 8
    msg += b'\x80'
    while len(msg) % 64 != 56:
        msg += b'\x00'
    msg += struct.pack('>Q', bit_len)
    return msg


def _sha1(data: bytes) -> bytes:
    """SHA-1 from scratch."""
    msg = _sha1_pad(data)
    H = list(_SHA1_H0)

    for i in range(0, len(msg), 64):
        chunk = msg[i:i+64]
        W = list(struct.unpack('>16I', chunk))
        for j in range(16, 80):
            W.append(_rotl(W[j-3] ^ W[j-8] ^ W[j-14] ^ W[j-16], 1))

        a, b, c, d, e = H
        for j in range(80):
            if j < 20:
                f = (b & c) | (~b & d)
                k = _SHA1_K[0]
            elif j < 40:
                f = b ^ c ^ d
                k = _SHA1_K[1]
            elif j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = _SHA1_K[2]
            else:
                f = b ^ c ^ d
                k = _SHA1_K[3]
            temp = (_rotl(a, 5) + f + e + k + W[j]) & _MASK32
            e, d, c, b, a = d, c, _rotl(b, 30), a, temp

        H[0] = (H[0] + a) & _MASK32
        H[1] = (H[1] + b) & _MASK32
        H[2] = (H[2] + c) & _MASK32
        H[3] = (H[3] + d) & _MASK32
        H[4] = (H[4] + e) & _MASK32

    return struct.pack('>5I', *H)


def _hmac_sha1(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA1 from scratch."""
    block_size = 64
    if len(key) > block_size:
        key = _sha1(key)
    key = key + b'\x00' * (block_size - len(key))
    i_pad = bytes(b ^ 0x36 for b in key)
    o_pad = bytes(b ^ 0x5C for b in key)
    return _sha1(o_pad + _sha1(i_pad + msg))


# ── Base32 decode (from scratch) ───────────────────────────────────────────────

_B32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
_B32_MAP = {c: i for i, c in enumerate(_B32_CHARS)}


def _base32_decode(s: str) -> bytes:
    s = s.upper().rstrip('=')
    bits = 0
    bit_count = 0
    out = bytearray()
    for ch in s:
        bits = (bits << 5) | _B32_MAP[ch]
        bit_count += 5
        if bit_count >= 8:
            bit_count -= 8
            out.append((bits >> bit_count) & 0xFF)
    return bytes(out)


def _base32_encode(data: bytes) -> str:
    bits = 0
    bit_count = 0
    out = []
    for byte in data:
        bits = (bits << 8) | byte
        bit_count += 8
        while bit_count >= 5:
            bit_count -= 5
            out.append(_B32_CHARS[(bits >> bit_count) & 0x1F])
    if bit_count > 0:
        out.append(_B32_CHARS[(bits << (5 - bit_count)) & 0x1F])
    # Pad
    while len(out) % 8 != 0:
        out.append('=')
    return ''.join(out)


# ── HOTP / TOTP ───────────────────────────────────────────────────────────────

def _hotp(key_bytes: bytes, counter: int, digits: int = 6) -> str:
    """RFC 4226 HOTP."""
    msg = struct.pack('>Q', counter)
    h = _hmac_sha1(key_bytes, msg)
    offset = h[-1] & 0x0F
    code = struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def generate_totp_secret() -> str:
    """Generate a random 20-byte (160-bit) base32 TOTP secret."""
    raw = os.urandom(20)
    return _base32_encode(raw)


def get_totp_code(secret: str, timestamp: float = None, step: int = 30, digits: int = 6) -> str:
    """Generate current TOTP code."""
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp) // step
    key_bytes = _base32_decode(secret)
    return _hotp(key_bytes, counter, digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify TOTP code. Allows ±window time steps to tolerate clock drift.
    """
    now = int(time.time()) // 30
    key_bytes = _base32_decode(secret)
    for delta in range(-window, window + 1):
        expected = _hotp(key_bytes, now + delta)
        if expected == str(code).strip():
            return True
    return False


def get_totp_uri(secret: str, account: str, issuer: str = "SovereignGuard") -> str:
    """Generate otpauth:// URI for QR code generation."""
    return f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits=6&period=30"
