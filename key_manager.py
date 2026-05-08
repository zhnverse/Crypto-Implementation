"""
Key Management Module — Sovereign Guard.
Handles RSA + ECC key generation, storage, rotation.
Private keys are stored XOR-masked with a master secret derived from
the user's password hash (so the DB alone cannot recover them).
"""

import os
import time

from crypto import rsa, ecc
from crypto.sha256 import sha256
from crypto.hmac_impl import hmac_sha256
import models

# Master secret — in production this would be in a hardware HSM / env var
_MASTER_SECRET = os.environ.get('SG_MASTER_SECRET', 'SovereignGuardMasterKey2026!!').encode()


# ── Key protection ─────────────────────────────────────────────────────────────

def _derive_wrap_key(user_password_hash: str) -> bytes:
    """
    Derive a 32-byte wrapping key from user password hash + master secret.
    Used to XOR-protect private keys at rest.
    """
    material = _MASTER_SECRET + user_password_hash.encode()
    return sha256(material)


def _xor_mask(data: bytes, key: bytes) -> bytes:
    """XOR data with key (cycling key if shorter)."""
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


def _protect_key(priv_bytes: bytes, wrap_key: bytes) -> str:
    """Encrypt private key with wrap key → hex string."""
    return _xor_mask(priv_bytes, wrap_key).hex()


def _unprotect_key(enc_hex: str, wrap_key: bytes) -> bytes:
    """Decrypt protected private key."""
    return _xor_mask(bytes.fromhex(enc_hex), wrap_key)


# ── RSA key generation & storage ──────────────────────────────────────────────

def generate_rsa_keys(password_hash: str) -> dict:
    """
    Generate RSA-2048 key pair.
    Returns dict with pub components + encrypted private key.
    """
    pub, priv = rsa.generate_keypair(bits=2048)
    e, n = pub
    d, _ = priv

    wrap_key = _derive_wrap_key(password_hash)

    # Serialize private key: d and n as big-endian bytes
    d_bytes = d.to_bytes(256, 'big')
    n_bytes = n.to_bytes(256, 'big')
    priv_bytes = d_bytes + n_bytes  # 512 bytes total

    priv_enc = _protect_key(priv_bytes, wrap_key)

    return {
        'rsa_pub_e': hex(e),
        'rsa_pub_n': hex(n),
        'rsa_priv_enc': priv_enc,
    }


def recover_rsa_private_key(user: dict, password_hash: str) -> tuple:
    """Recover RSA private key (d, n) from stored encrypted blob."""
    wrap_key = _derive_wrap_key(password_hash)
    priv_bytes = _unprotect_key(user['rsa_priv_enc'], wrap_key)
    d = int.from_bytes(priv_bytes[:256], 'big')
    n = int.from_bytes(priv_bytes[256:], 'big')
    return (d, n)


def get_rsa_public_key(user: dict) -> tuple:
    """Return RSA public key (e, n) from user record."""
    return (int(user['rsa_pub_e'], 16), int(user['rsa_pub_n'], 16))


# ── ECC key generation & storage ──────────────────────────────────────────────

def generate_ecc_keys(password_hash: str) -> dict:
    """
    Generate ECC P-256 key pair.
    Returns dict with pub components + encrypted private key.
    """
    pub, priv = ecc.generate_keypair()

    wrap_key = _derive_wrap_key(password_hash)
    priv_bytes = priv.to_bytes(32, 'big')
    priv_enc = _protect_key(priv_bytes, wrap_key)

    return {
        'ecc_pub_x': hex(pub.x),
        'ecc_pub_y': hex(pub.y),
        'ecc_priv_enc': priv_enc,
    }


def recover_ecc_private_key(user: dict, password_hash: str) -> int:
    """Recover ECC private key scalar from stored encrypted blob."""
    wrap_key = _derive_wrap_key(password_hash)
    priv_bytes = _unprotect_key(user['ecc_priv_enc'], wrap_key)
    return int.from_bytes(priv_bytes, 'big')


def get_ecc_public_key(user: dict) -> ecc.Point:
    """Return ECC public key Point from user record."""
    return ecc.Point(int(user['ecc_pub_x'], 16), int(user['ecc_pub_y'], 16))


# ── HMAC integrity tag ────────────────────────────────────────────────────────

_INTEGRITY_KEY = sha256(_MASTER_SECRET + b':integrity')


def compute_user_hmac(user_id: int, username_enc: str, email_enc: str) -> str:
    """Compute HMAC-SHA256 integrity tag for a user row."""
    msg = f"{user_id}|{username_enc}|{email_enc}".encode()
    return hmac_sha256(_INTEGRITY_KEY, msg).hex()


def compute_post_hmac(post_id_or_user: str, title_enc: str, content_enc: str) -> str:
    """Compute HMAC-SHA256 integrity tag for a post row."""
    msg = f"{post_id_or_user}|{title_enc}|{content_enc}".encode()
    return hmac_sha256(_INTEGRITY_KEY, msg).hex()


def verify_user_integrity(user: dict) -> bool:
    expected = compute_user_hmac(user['id'], user['username_enc'], user['email_enc'])
    return expected == user['hmac_tag']


def verify_post_integrity(post: dict) -> bool:
    expected = compute_post_hmac(str(post['user_id']), post['title_enc'], post['content_enc'])
    return expected == post['hmac_tag']


# ── Key Rotation ──────────────────────────────────────────────────────────────

def rotate_keys_for_user(user_id: int, password_hash: str):
    """
    Admin-triggered key rotation:
    1. Generate new RSA + ECC key pairs
    2. Re-encrypt all posts for this user with new ECC key
    3. Re-encrypt profile fields with new RSA key
    4. Store old key versions in key_store (deactivated)
    5. Update users table with new key material
    """
    user = models.get_user_by_id(user_id)
    if not user:
        raise ValueError("User not found")

    # Get current private keys
    old_rsa_priv = recover_rsa_private_key(user, password_hash)
    old_ecc_priv = recover_ecc_private_key(user, password_hash)

    # Archive old keys in key_store
    old_rsa_version = _get_next_version(user_id, 'rsa')
    old_ecc_version = _get_next_version(user_id, 'ecc')

    models.store_key({
        'user_id': user_id,
        'key_type': 'rsa',
        'key_version': old_rsa_version,
        'pub_data': f"{user['rsa_pub_e']}:{user['rsa_pub_n']}",
        'priv_enc': user['rsa_priv_enc'],
        'active': 0,
        'created_at': time.time(),
    })

    models.store_key({
        'user_id': user_id,
        'key_type': 'ecc',
        'key_version': old_ecc_version,
        'pub_data': f"{user['ecc_pub_x']}:{user['ecc_pub_y']}",
        'priv_enc': user['ecc_priv_enc'],
        'active': 0,
        'created_at': time.time(),
    })

    # Generate new keys
    new_rsa = generate_rsa_keys(password_hash)
    new_ecc = generate_ecc_keys(password_hash)

    # Re-encrypt user profile fields with new RSA key
    new_rsa_pub = (int(new_rsa['rsa_pub_e'], 16), int(new_rsa['rsa_pub_n'], 16))
    new_rsa_priv = recover_rsa_private_key({
        'rsa_priv_enc': new_rsa['rsa_priv_enc'],
    }, password_hash) if False else None  # just generated, handled below

    # Decrypt profile with old RSA key
    username_plain = rsa.decrypt(bytes.fromhex(user['username_enc']), old_rsa_priv).decode()
    email_plain = rsa.decrypt(bytes.fromhex(user['email_enc']), old_rsa_priv).decode()
    phone_plain = rsa.decrypt(bytes.fromhex(user['phone_enc']), old_rsa_priv).decode()

    # Re-encrypt with new RSA key
    new_rsa_pub_tuple = (int(new_rsa['rsa_pub_e'], 16), int(new_rsa['rsa_pub_n'], 16))
    new_username_enc = rsa.encrypt(username_plain.encode(), new_rsa_pub_tuple).hex()
    new_email_enc    = rsa.encrypt(email_plain.encode(), new_rsa_pub_tuple).hex()
    new_phone_enc    = rsa.encrypt(phone_plain.encode(), new_rsa_pub_tuple).hex()
    new_hmac = compute_user_hmac(user_id, new_username_enc, new_email_enc)

    # Re-encrypt posts with new ECC key
    new_ecc_pub = ecc.Point(int(new_ecc['ecc_pub_x'], 16), int(new_ecc['ecc_pub_y'], 16))
    posts = models.get_posts_by_user(user_id)
    for post in posts:
        old_ecc_priv_key = old_ecc_priv
        title_plain   = ecc.decrypt(bytes.fromhex(post['title_enc']),   old_ecc_priv_key).decode()
        content_plain = ecc.decrypt(bytes.fromhex(post['content_enc']), old_ecc_priv_key).decode()
        new_title_enc   = ecc.encrypt(title_plain.encode(), new_ecc_pub).hex()
        new_content_enc = ecc.encrypt(content_plain.encode(), new_ecc_pub).hex()
        new_post_hmac   = compute_post_hmac(str(user_id), new_title_enc, new_content_enc)
        models.update_post(post['id'], new_title_enc, new_content_enc, new_post_hmac, time.time())

    # Update user record with new keys and re-encrypted profile
    models.update_user_keys(
        user_id,
        new_rsa['rsa_pub_e'], new_rsa['rsa_pub_n'], new_rsa['rsa_priv_enc'],
        new_ecc['ecc_pub_x'], new_ecc['ecc_pub_y'], new_ecc['ecc_priv_enc'],
    )
    models.update_user_profile(
        user_id, new_username_enc, new_email_enc, new_phone_enc,
        user['username_hash'], new_hmac
    )

    models.log_action(user_id, 'KEY_ROTATION', f'RSA v{old_rsa_version}, ECC v{old_ecc_version}')


def _get_next_version(user_id: int, key_type: str) -> int:
    keys = models.get_all_key_versions(user_id)
    versions = [k['key_version'] for k in keys if k['key_type'] == key_type]
    return max(versions, default=0) + 1
