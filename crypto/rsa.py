"""
RSA Encryption — implemented from scratch.
Used for encrypting USER PROFILE FIELDS (username, email, phone, etc.)

Algorithms mirror CE447_Lab_5_RSA.ipynb exactly:
  - extended_gcd (recursive Extended Euclidean) → mod_inverse (d·e ≡ 1 mod φ(n))
  - _miller_rabin primality test
  - _random_prime for 1024-bit primes (→ 2048-bit n)
  - _mod_exp: square-and-multiply (fast modular exponentiation)
  - e = 65537

Key size: 2048-bit
Padding:  OAEP-like (XOR mask with SHA-256 via MGF1)
"""

import os
import struct
from .sha256 import sha256

# ── Extended Euclidean Algorithm (Lab 5 style) ─────────────────────────────────

def extended_gcd(a, b):
    """
    Recursive Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd.
    (Mirrors Lab 5 notebook exactly.)
    """
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y


def mod_inverse(e, phi):
    """
    Compute d such that d*e ≡ 1 (mod phi) using the Extended Euclidean Algorithm.
    Raises ValueError if inverse does not exist.
    (Mirrors Lab 5 notebook exactly.)
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist (e and phi are not coprime).")
    return x % phi  # Ensure d is positive


# ── Fast Modular Exponentiation (Lab 5 style — square-and-multiply) ────────────

def _mod_exp(base, exp, mod):
    """
    Fast modular exponentiation (square-and-multiply).
    Equivalent to pow(base, exp, mod) but implemented from scratch.
    """
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        exp >>= 1
        base = base * base % mod
    return result


# ── Miller-Rabin Primality Test ────────────────────────────────────────────────

def _miller_rabin(n, rounds=20):
    """
    Miller-Rabin primality test.
    Uses deterministic witnesses for numbers < 3.3 × 10^24.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Deterministic witnesses for n < 3,317,044,064,679,887,385,961,981
    witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for a in witnesses:
        if a >= n:
            continue
        x = _mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = _mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits):
    """
    Generate a random prime of exactly `bits` bits.
    Sets top two bits (ensuring full size) and the bottom bit (odd).
    Mirrors sympy.randprime(2^(bits-1), 2^bits) used in Lab 5.
    """
    while True:
        n = int.from_bytes(os.urandom(bits // 8), 'big')
        # Set the top two bits (full-width) and bottom bit (odd)
        n |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _miller_rabin(n):
            return n


# ── RSA Key Generation (Lab 5 algorithm, scaled to 2048-bit) ──────────────────

def generate_keypair(bits=2048):
    """
    Generate RSA key pair using Lab 5 algorithm:
      p, q  = distinct random (bits/2)-bit primes
      n     = p * q
      phi   = (p-1)*(q-1)
      e     = 65537  (verified coprime to phi via gcd check)
      d     = mod_inverse(e, phi)  ← extended_gcd from Lab 5

    Returns: (public_key, private_key)
      public_key  = (e, n)
      private_key = (d, n)
    """
    half = bits // 2
    e = 65537  # standard public exponent

    while True:
        p = _random_prime(half)
        q = _random_prime(half)

        # Make sure p and q are distinct (Lab 5 pattern)
        while q == p:
            q = _random_prime(half)

        n = p * q
        phi = (p - 1) * (q - 1)

        # Verify e is coprime to phi (gcd must be 1), then compute d
        gcd, _, _ = extended_gcd(e, phi)
        if gcd != 1:
            continue  # very rare; regenerate primes

        try:
            d = mod_inverse(e, phi)
            break
        except ValueError:
            continue

    return (e, n), (d, n)


# ── OAEP-like Padding ──────────────────────────────────────────────────────────

def _mgf1(seed: bytes, length: int) -> bytes:
    """Mask Generation Function 1 using SHA-256."""
    out = b''
    counter = 0
    while len(out) < length:
        C = struct.pack('>I', counter)
        out += sha256(seed + C)
        counter += 1
    return out[:length]


HASH_LEN = 32           # SHA-256 output length
LABEL_HASH = sha256(b'')  # hash of empty label


def _oaep_encode(msg: bytes, mod_bytes: int) -> bytes:
    """OAEP encode message for RSA encryption."""
    k = mod_bytes
    m_len = len(msg)
    if m_len > k - 2 * HASH_LEN - 2:
        raise ValueError("Message too long for RSA key size")

    ps = b'\x00' * (k - m_len - 2 * HASH_LEN - 2)
    db = LABEL_HASH + ps + b'\x01' + msg
    seed = os.urandom(HASH_LEN)
    db_mask = _mgf1(seed, k - HASH_LEN - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1(masked_db, HASH_LEN)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return b'\x00' + masked_seed + masked_db


def _oaep_decode(em: bytes) -> bytes:
    """OAEP decode."""
    if em[0] != 0:
        raise ValueError("OAEP decoding error")
    masked_seed = em[1:1 + HASH_LEN]
    masked_db   = em[1 + HASH_LEN:]
    seed_mask   = _mgf1(masked_db, HASH_LEN)
    seed        = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask     = _mgf1(seed, len(masked_db))
    db          = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    if db[:HASH_LEN] != LABEL_HASH:
        raise ValueError("OAEP label hash mismatch")

    idx = HASH_LEN
    while idx < len(db) and db[idx] == 0:
        idx += 1
    if idx >= len(db) or db[idx] != 1:
        raise ValueError("OAEP padding error")
    return db[idx + 1:]


# ── Encrypt / Decrypt ──────────────────────────────────────────────────────────

def encrypt(plaintext: bytes, public_key: tuple) -> bytes:
    """
    Encrypt plaintext bytes with RSA-OAEP.
    c = m^e (mod n)  — Lab 5 formula, implemented via _mod_exp from scratch.
    Handles arbitrary-length messages by splitting into OAEP blocks.
    """
    e, n = public_key
    mod_bytes = (n.bit_length() + 7) // 8
    max_chunk = mod_bytes - 2 * HASH_LEN - 2

    ciphertext_blocks = []
    for i in range(0, len(plaintext), max_chunk):
        chunk = plaintext[i:i + max_chunk]
        em    = _oaep_encode(chunk, mod_bytes)
        m_int = int.from_bytes(em, 'big')
        # c = m^e mod n  (Lab 5: c = pow(m, e, n))
        c_int   = _mod_exp(m_int, e, n)
        c_bytes = c_int.to_bytes(mod_bytes, 'big')
        ciphertext_blocks.append(c_bytes)

    # Prepend block count for decryption
    num_blocks = len(ciphertext_blocks)
    result = struct.pack('>I', num_blocks)
    for block in ciphertext_blocks:
        result += block
    return result


def decrypt(ciphertext: bytes, private_key: tuple) -> bytes:
    """
    Decrypt RSA-OAEP ciphertext.
    m = c^d (mod n)  — Lab 5 formula, implemented via _mod_exp from scratch.
    """
    d, n = private_key
    mod_bytes = (n.bit_length() + 7) // 8

    num_blocks = struct.unpack('>I', ciphertext[:4])[0]
    offset = 4
    plaintext = b''

    for _ in range(num_blocks):
        c_bytes = ciphertext[offset:offset + mod_bytes]
        offset += mod_bytes
        c_int = int.from_bytes(c_bytes, 'big')
        # m = c^d mod n  (Lab 5: m_decrypted = pow(c, d, n))
        m_int = _mod_exp(c_int, d, n)
        em    = m_int.to_bytes(mod_bytes, 'big')
        plaintext += _oaep_decode(em)

    return plaintext


# ── Serialization helpers ──────────────────────────────────────────────────────

def serialize_public_key(pub: tuple) -> str:
    """Serialize (e, n) as hex string 'e:n'."""
    e, n = pub
    return f"{hex(e)}:{hex(n)}"


def deserialize_public_key(s: str) -> tuple:
    parts = s.split(':', 1)
    return (int(parts[0], 16), int(parts[1], 16))


def serialize_private_key(priv: tuple) -> str:
    d, n = priv
    return f"{hex(d)}:{hex(n)}"


def deserialize_private_key(s: str) -> tuple:
    parts = s.split(':', 1)
    return (int(parts[0], 16), int(parts[1], 16))
