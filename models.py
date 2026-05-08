"""
Database models and initialization for Sovereign Guard.
Uses SQLite via sqlite3.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'sovereign.db')


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        -- encrypted profile fields (RSA-OAEP)
        username_enc    TEXT NOT NULL UNIQUE,
        email_enc       TEXT NOT NULL,
        phone_enc       TEXT NOT NULL,
        -- plain username index for login lookup (hashed for privacy)
        username_hash   TEXT NOT NULL UNIQUE,
        -- password
        password_hash   TEXT NOT NULL,
        salt            TEXT NOT NULL,
        -- keys: RSA for profile fields
        rsa_pub_e       TEXT NOT NULL,
        rsa_pub_n       TEXT NOT NULL,
        rsa_priv_enc    TEXT NOT NULL,    -- private key XOR-masked with master key
        -- keys: ECC for posts
        ecc_pub_x       TEXT NOT NULL,
        ecc_pub_y       TEXT NOT NULL,
        ecc_priv_enc    TEXT NOT NULL,    -- private key XOR-masked
        -- role
        role            TEXT NOT NULL DEFAULT 'user',
        -- 2FA
        totp_secret     TEXT NOT NULL,
        totp_enabled    INTEGER NOT NULL DEFAULT 1,
        -- HMAC integrity tag for this row
        hmac_tag        TEXT NOT NULL,
        -- session
        session_token   TEXT,
        session_expiry  REAL,
        -- timestamps
        created_at      REAL NOT NULL,
        last_login      REAL
    );

    CREATE TABLE IF NOT EXISTS posts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id         INTEGER NOT NULL REFERENCES users(id),
        -- ECC-ECIES encrypted fields
        title_enc       TEXT NOT NULL,
        content_enc     TEXT NOT NULL,
        -- HMAC integrity tag
        hmac_tag        TEXT NOT NULL,
        created_at      REAL NOT NULL,
        updated_at      REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS key_store (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id         INTEGER NOT NULL REFERENCES users(id),
        key_type        TEXT NOT NULL,       -- 'rsa' or 'ecc'
        key_version     INTEGER NOT NULL DEFAULT 1,
        pub_data        TEXT NOT NULL,
        priv_enc        TEXT NOT NULL,
        active          INTEGER NOT NULL DEFAULT 1,
        created_at      REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id         INTEGER,
        action          TEXT NOT NULL,
        detail          TEXT,
        ip              TEXT,
        ts              REAL NOT NULL
    );
    """)

    conn.commit()
    conn.close()


# ── User helpers ───────────────────────────────────────────────────────────────

def create_user(data: dict):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO users (
            username_enc, email_enc, phone_enc, username_hash,
            password_hash, salt,
            rsa_pub_e, rsa_pub_n, rsa_priv_enc,
            ecc_pub_x, ecc_pub_y, ecc_priv_enc,
            role, totp_secret, totp_enabled,
            hmac_tag, created_at
        ) VALUES (
            :username_enc, :email_enc, :phone_enc, :username_hash,
            :password_hash, :salt,
            :rsa_pub_e, :rsa_pub_n, :rsa_priv_enc,
            :ecc_pub_x, :ecc_pub_y, :ecc_priv_enc,
            :role, :totp_secret, :totp_enabled,
            :hmac_tag, :created_at
        )
    """, data)
    user_id = c.lastrowid
    conn.commit()
    conn.close()
    return user_id


def get_user_by_username_hash(username_hash: str):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username_hash = ?", (username_hash,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_users():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_user_session(user_id: int, token: str, expiry: float):
    conn = get_conn()
    conn.execute(
        "UPDATE users SET session_token=?, session_expiry=?, last_login=? WHERE id=?",
        (token, expiry, expiry, user_id)
    )
    conn.commit()
    conn.close()


def clear_user_session(user_id: int):
    conn = get_conn()
    conn.execute(
        "UPDATE users SET session_token=NULL, session_expiry=NULL WHERE id=?",
        (user_id,)
    )
    conn.commit()
    conn.close()


def update_user_profile(user_id: int, username_enc: str, email_enc: str,
                         phone_enc: str, username_hash: str, hmac_tag: str):
    conn = get_conn()
    conn.execute("""
        UPDATE users SET username_enc=?, email_enc=?, phone_enc=?,
        username_hash=?, hmac_tag=? WHERE id=?
    """, (username_enc, email_enc, phone_enc, username_hash, hmac_tag, user_id))
    conn.commit()
    conn.close()


def update_user_keys(user_id: int, rsa_pub_e, rsa_pub_n, rsa_priv_enc,
                      ecc_pub_x, ecc_pub_y, ecc_priv_enc):
    conn = get_conn()
    conn.execute("""
        UPDATE users SET rsa_pub_e=?, rsa_pub_n=?, rsa_priv_enc=?,
        ecc_pub_x=?, ecc_pub_y=?, ecc_priv_enc=? WHERE id=?
    """, (rsa_pub_e, rsa_pub_n, rsa_priv_enc, ecc_pub_x, ecc_pub_y, ecc_priv_enc, user_id))
    conn.commit()
    conn.close()


def update_user_role(user_id: int, role: str):
    conn = get_conn()
    conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    conn.commit()
    conn.close()


# ── Post helpers ───────────────────────────────────────────────────────────────

def create_post(data: dict) -> int:
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO posts (user_id, title_enc, content_enc, hmac_tag, created_at, updated_at)
        VALUES (:user_id, :title_enc, :content_enc, :hmac_tag, :created_at, :updated_at)
    """, data)
    post_id = c.lastrowid
    conn.commit()
    conn.close()
    return post_id


def get_post_by_id(post_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM posts WHERE id=?", (post_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_posts_by_user(user_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM posts WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_posts():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM posts ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_post(post_id: int, title_enc: str, content_enc: str, hmac_tag: str, updated_at: float):
    conn = get_conn()
    conn.execute("""
        UPDATE posts SET title_enc=?, content_enc=?, hmac_tag=?, updated_at=? WHERE id=?
    """, (title_enc, content_enc, hmac_tag, updated_at, post_id))
    conn.commit()
    conn.close()


def delete_post(post_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM posts WHERE id=?", (post_id,))
    conn.commit()
    conn.close()


# ── Key store helpers ──────────────────────────────────────────────────────────

def store_key(data: dict):
    conn = get_conn()
    conn.execute("""
        INSERT INTO key_store (user_id, key_type, key_version, pub_data, priv_enc, active, created_at)
        VALUES (:user_id, :key_type, :key_version, :pub_data, :priv_enc, :active, :created_at)
    """, data)
    conn.commit()
    conn.close()


def get_active_keys(user_id: int, key_type: str):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM key_store WHERE user_id=? AND key_type=? AND active=1
        ORDER BY key_version DESC LIMIT 1
    """, (user_id, key_type))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_key_versions(user_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM key_store WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def deactivate_old_keys(user_id: int, key_type: str):
    conn = get_conn()
    conn.execute(
        "UPDATE key_store SET active=0 WHERE user_id=? AND key_type=?",
        (user_id, key_type)
    )
    conn.commit()
    conn.close()


# ── Audit log ──────────────────────────────────────────────────────────────────

def log_action(user_id, action: str, detail: str = '', ip: str = ''):
    import time
    conn = get_conn()
    conn.execute(
        "INSERT INTO audit_log (user_id, action, detail, ip, ts) VALUES (?,?,?,?,?)",
        (user_id, action, detail, ip, time.time())
    )
    conn.commit()
    conn.close()


def get_audit_logs(limit=200):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]
