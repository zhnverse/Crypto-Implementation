"""
ECC (Elliptic Curve Cryptography) — ECIES over NIST P-256, from scratch.
Used for encrypting POST CONTENT.

Curve:  NIST P-256 (secp256r1)
Scheme: ECIES — Ephemeral ECDH + XOR stream cipher (keyed via SHA-256)

Point arithmetic algorithms mirror CSE447_Lab_7_ECC.ipynb exactly:
  - inverse_mod : uses pow(k, -1, p)  ← Lab 7 style
  - point_add   : single function handling both addition AND doubling
                  (same branching logic as Lab 7)
  - scalar_mult : double-and-add loop (same as Lab 7)
"""

import os
import struct
from .sha256 import sha256

# ── NIST P-256 Parameters ──────────────────────────────────────────────────────

P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # group order
H  = 1  # cofactor


class Point:
    """Affine point on the curve (or the point at infinity)."""
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "Point(infinity)"
        return f"Point(x={hex(self.x)}, y={hex(self.y)})"


INFINITY = Point(None, None)
G = Point(GX, GY)


# ── Modular Inverse (Lab 7 style) ──────────────────────────────────────────────

def inverse_mod(k, p):
    """
    Modular inverse of k mod p.
    Mirrors Lab 7: return pow(k, -1, p)
    pow(k, -1, p) uses the extended Euclidean algorithm internally — no library.
    """
    return pow(k, -1, p)


# ── Point Addition — handles both addition AND doubling (Lab 7 style) ──────────

def point_add(P1, P2, a=A, p=P):
    """
    Add two points on the elliptic curve.
    Mirrors CSE447_Lab_7_ECC.ipynb point_add exactly:
      - return Q if P is None (point at infinity)
      - return P if Q is None
      - if vertical reflection (P + (-P)), return None (infinity)
      - if P == Q (doubling): m = (3x²+a) * inverse_mod(2y, p) % p
      - else (addition):      m = (y2-y1) * inverse_mod(x2-x1, p) % p
      - x_r = (m²-x1-x2) % p
      - y_r = (m*(x1-x_r)-y1) % p

    Returns a Point, or None to represent the point at infinity.
    None ↔ INFINITY are both handled by scalar_mult.
    """
    if P1 is None or P1.is_infinity():
        return P2
    if P2 is None or P2.is_infinity():
        return P1

    x1, y1 = P1.x, P1.y
    x2, y2 = P2.x, P2.y

    # Vertical reflection → point at infinity
    if x1 == x2 and (y1 + y2) % p == 0:
        return INFINITY

    if P1 == P2:
        # Point doubling
        m = (3 * x1 ** 2 + a) * inverse_mod(2 * y1, p) % p
    else:
        # Point addition
        m = (y2 - y1) * inverse_mod(x2 - x1, p) % p

    x_r = (m ** 2 - x1 - x2) % p
    y_r = (m * (x1 - x_r) - y1) % p

    return Point(x_r, y_r)


# ── Scalar Multiplication — double-and-add (Lab 7 style) ──────────────────────

def scalar_mult(k: int, P1) -> 'Point':
    """
    Double-and-add scalar multiplication: returns k * P1.
    Mirrors CSE447_Lab_7_ECC.ipynb scalar_mult exactly:
      R = None  (point at infinity)
      Q = P
      while k > 0:
          if k & 1: R = point_add(R, Q)
          Q = point_add(Q, Q)   # doubling
          k >>= 1
      return R
    """
    R = INFINITY   # point at infinity
    Q = P1

    while k > 0:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)    # doubling handled inside point_add
        k >>= 1

    return R


# ── Key Generation ────────────────────────────────────────────────────────────

def generate_keypair():
    """
    Generate ECC key pair on P-256.
    Returns: (public_key_point, private_key_int)
    """
    priv = int.from_bytes(os.urandom(32), 'big') % (N - 1) + 1
    pub  = scalar_mult(priv, G)
    return pub, priv


# ── ECIES Encryption / Decryption ─────────────────────────────────────────────

def _kdf(shared_secret_point: Point) -> bytes:
    """Derive a 32-byte key from shared secret point x-coordinate via SHA-256."""
    coord = shared_secret_point.x.to_bytes(32, 'big')
    return sha256(coord)


def _xor_stream(key: bytes, data: bytes) -> bytes:
    """XOR-based stream cipher keyed from SHA-256 blocks."""
    out = bytearray()
    block_num = 0
    pos = 0
    keystream = b''
    for byte in data:
        if pos >= len(keystream):
            keystream = sha256(key + struct.pack('>I', block_num))
            block_num += 1
            pos = 0
        out.append(byte ^ keystream[pos])
        pos += 1
    return bytes(out)


def encrypt(plaintext: bytes, pub_key: Point) -> bytes:
    """
    ECIES Encrypt:
      1. Generate ephemeral key pair (r, R = r*G)     — scalar_mult Lab 7 style
      2. Compute shared secret S = r * pub_key        — ECDH, Lab 7 style
      3. Derive encryption key K = KDF(S)
      4. Encrypt: C = XOR_stream(K, plaintext)
      5. Compute MAC tag T = HMAC-SHA256(K, R_bytes || C)
      6. Output: R_bytes (64) || T (32) || C
    """
    from .hmac_impl import hmac_sha256

    r = int.from_bytes(os.urandom(32), 'big') % (N - 1) + 1
    R = scalar_mult(r, G)
    S = scalar_mult(r, pub_key)

    K = _kdf(S)

    R_bytes = R.x.to_bytes(32, 'big') + R.y.to_bytes(32, 'big')  # 64 bytes
    C = _xor_stream(K, plaintext)
    T = hmac_sha256(K, R_bytes + C)   # 32-byte MAC

    return R_bytes + T + C


def decrypt(ciphertext: bytes, priv_key: int) -> bytes:
    """
    ECIES Decrypt:
      1. Parse R, T, C from ciphertext
      2. Compute shared secret S = priv_key * R   — scalar_mult Lab 7 style
      3. Derive key K = KDF(S)
      4. Verify MAC T
      5. Decrypt: plaintext = XOR_stream(K, C)
    """
    from .hmac_impl import hmac_sha256, verify_hmac

    if len(ciphertext) < 64 + 32:
        raise ValueError("Ciphertext too short")

    R_bytes = ciphertext[:64]
    T       = ciphertext[64:96]
    C       = ciphertext[96:]

    Rx = int.from_bytes(R_bytes[:32], 'big')
    Ry = int.from_bytes(R_bytes[32:], 'big')
    R  = Point(Rx, Ry)

    S = scalar_mult(priv_key, R)
    K = _kdf(S)

    if not verify_hmac(K, R_bytes + C, T):
        raise ValueError("ECIES MAC verification failed — data integrity compromised")

    return _xor_stream(K, C)


# ── Serialization ─────────────────────────────────────────────────────────────

def serialize_public_key(pub: Point) -> str:
    return f"{hex(pub.x)}:{hex(pub.y)}"


def deserialize_public_key(s: str) -> Point:
    parts = s.split(':', 1)
    return Point(int(parts[0], 16), int(parts[1], 16))


def serialize_private_key(priv: int) -> str:
    return hex(priv)


def deserialize_private_key(s: str) -> int:
    return int(s, 16)
