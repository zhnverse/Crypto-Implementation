# 🛡 Sovereign Guard

**Secure System for User Data and Social Posts using RSA/ECC**
CSE447 — Cryptography and Cryptanalysis | Spring 2026

---

## Overview

Sovereign Guard is a full-stack secure social platform built with **Python + Flask + SQLite**.
All cryptographic algorithms are implemented **from scratch** — no built-in framework encryption functions are used.

---

## Cryptographic Architecture

| Component | Algorithm | Implementation |
|---|---|---|
| Profile encryption (username, email, phone) | **RSA-2048 OAEP** | From scratch (Miller-Rabin primality, modular exp, MGF1) |
| Post encryption (title, content) | **ECC P-256 ECIES** | From scratch (point arithmetic, scalar mult, XOR stream) |
| Password storage | **PBKDF2-SHA256** | From scratch (iterated HMAC-SHA256) |
| Data integrity | **HMAC-SHA256** | From scratch (RFC 2104) |
| Two-factor auth | **TOTP RFC 6238** | From scratch (HMAC-SHA1, Base32) |
| Session tokens | **HMAC-SHA256 signed** | From scratch |
| Hashing primitive | **SHA-256** | From scratch (FIPS 180-4) |

---

## Project Structure

```
sovereign_guard/
├── app.py                  # Flask application & routes
├── models.py               # SQLite schema & DB helpers
├── key_manager.py          # Key generation, wrapping, rotation
├── requirements.txt        # Only Flask needed
├── crypto/
│   ├── sha256.py           # SHA-256 from scratch (FIPS 180-4)
│   ├── hmac_impl.py        # HMAC-SHA256 from scratch (RFC 2104)
│   ├── hash_password.py    # PBKDF2-SHA256 from scratch
│   ├── rsa.py              # RSA-2048 OAEP from scratch
│   ├── ecc.py              # ECC P-256 ECIES from scratch
│   └── totp.py             # TOTP + SHA-1 + Base32 from scratch
├── templates/
│   ├── base.html
│   ├── index.html          # Landing page
│   ├── register.html       # Registration
│   ├── login.html          # Login
│   ├── setup_2fa.html      # TOTP setup with QR code
│   ├── verify_2fa.html     # TOTP entry
│   ├── feed.html           # Post feed
│   ├── post_new.html       # Create post
│   ├── post_edit.html      # Edit post
│   ├── profile.html        # View profile
│   ├── profile_edit.html   # Edit profile
│   ├── error.html          # 403/404
│   └── admin/
│       ├── users.html      # Admin: user management
│       ├── keys.html       # Admin: key management & rotation
│       └── logs.html       # Admin: audit log
└── static/
    ├── style.css           # Premium dark-mode UI
    └── app.js              # Frontend interactions
```

---

## Setup & Run

```bash
# 1. Install dependency
pip3 install flask

# 2. Run the server
cd sovereign_guard
python3 app.py
```

Open **http://localhost:5000** in your browser.

---

## First-Time Use

1. **Register** — the **first** registered account automatically becomes **Admin**
2. On the **2FA Setup** page, note the TOTP secret (use with Google Authenticator or enter displayed code)
3. **Login** → enter TOTP code → access the feed
4. Admin can manage users, rotate keys, and view audit logs at `/admin/*`

---

## Security Features

### Encryption
- **RSA-2048**: Each user gets a unique key pair at registration. Public key encrypts profile fields; private key is XOR-masked with a wrap key derived from master secret + password hash.
- **ECC P-256 ECIES**: Each user gets a unique ECC key pair. Posts encrypted with ephemeral ECDH + XOR stream keyed by SHA-256 of shared secret.

### Integrity
- Every user row and post has an **HMAC-SHA256** tag. Verified on every read. Tampering is detected and flagged in the UI.

### Password Security
- Passwords hashed with **PBKDF2-SHA256** (10,000 iterations) + 256-bit random salt.

### Two-Factor Authentication
- TOTP per RFC 6238, using HMAC-SHA1 and Base32 — all implemented from scratch.
- ±1 time step (30s) tolerance for clock drift.

### Session Management
- Session token = `base64(JSON payload) + HMAC-SHA256 signature`
- Stored as `HttpOnly` cookie. Verified on every protected request.
- 24-hour expiry.

### Role-Based Access Control
- **Admin**: view all users, manage keys, rotate keys, view audit logs, delete any post, assign roles
- **User**: create/edit/delete own posts, view/edit own profile

### Key Management
- Per-user RSA and ECC key pairs stored encrypted in the database
- Admin-triggered key rotation: generates new keys, re-encrypts all profile fields and posts, archives old key versions

---

## Database Schema

All sensitive fields stored as **hex-encoded ciphertext**:

```
users: username_enc, email_enc, phone_enc (RSA ciphertext)
       rsa_priv_enc, ecc_priv_enc (XOR-wrapped private keys)
       password_hash, salt (PBKDF2)
       hmac_tag (HMAC-SHA256 integrity)

posts: title_enc, content_enc (ECC ECIES ciphertext)
       hmac_tag (HMAC-SHA256 integrity)

key_store: versioned key archive for rotation history
audit_log: all security events with timestamp and IP
```
