"""
Sovereign Guard — Secure System for User Data and Social Posts
Main Flask Application

Features:
  - RSA-2048 OAEP encryption for user profile fields (from scratch)
  - ECC P-256 ECIES encryption for post content (from scratch)
  - SHA-256 + HMAC-SHA256 password hashing (from scratch)
  - TOTP 2FA (from scratch)
  - HMAC-SHA256 data integrity tags (from scratch)
  - HMAC-signed session tokens (from scratch)
  - Role-Based Access Control (Admin / User)
  - Key management and rotation
"""

import os
import time
import base64
import struct
import json
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, make_response, flash, abort, session as flask_session)

import models
import key_manager
from crypto import rsa, ecc
from crypto.hash_password import hash_password, verify_password
from crypto.totp import generate_totp_secret, get_totp_code, verify_totp, get_totp_uri
from crypto.hmac_impl import hmac_sha256, verify_hmac
from crypto.sha256 import sha256

app = Flask(__name__)
app.secret_key = os.environ.get('SG_FLASK_SECRET', 'sg-flask-dev-secret-2026')

@app.template_filter('strftime')
def _strftime(ts, fmt='%b %d, %Y'):
    try:
        return time.strftime(fmt, time.localtime(int(ts)))
    except Exception:
        return str(ts)

# ── Session config ─────────────────────────────────────────────────────────────
SESSION_DURATION = 86400        # 24 hours
TOKEN_HMAC_KEY = sha256(b'SovereignGuardSessionKey:v1')

# ── Session helpers ────────────────────────────────────────────────────────────

def _make_token(user_id: int, role: str, expiry: float) -> str:
    """
    Create HMAC-SHA256 signed session token.
    Format: base64(json_payload) + '.' + hmac_hex
    """
    payload = json.dumps({'uid': user_id, 'role': role, 'exp': expiry}).encode()
    b64 = base64.urlsafe_b64encode(payload).decode()
    tag = hmac_sha256(TOKEN_HMAC_KEY, payload).hex()
    return f"{b64}.{tag}"


def _verify_token(token: str):
    """
    Verify and decode session token.
    Returns (user_id, role) or raises ValueError.
    """
    try:
        b64, tag = token.rsplit('.', 1)
        payload = base64.urlsafe_b64decode(b64 + '==')
        if not verify_hmac(TOKEN_HMAC_KEY, payload, bytes.fromhex(tag)):
            raise ValueError("Token HMAC invalid")
        data = json.loads(payload)
        if data['exp'] < time.time():
            raise ValueError("Token expired")
        return data['uid'], data['role']
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")


def set_session(response, user_id: int, role: str):
    """Set HMAC-signed session cookie."""
    expiry = time.time() + SESSION_DURATION
    token = _make_token(user_id, role, expiry)
    models.update_user_session(user_id, token, expiry)
    response.set_cookie('sg_token', token, httponly=True,
                         samesite='Lax', max_age=SESSION_DURATION)
    return response


def get_current_user():
    """
    Read and verify session cookie.
    Returns (user_dict, role) or (None, None).
    """
    token = request.cookies.get('sg_token')
    if not token:
        return None, None
    try:
        user_id, role = _verify_token(token)
        user = models.get_user_by_id(user_id)
        if not user or user.get('session_token') != token:
            return None, None
        return user, role
    except ValueError:
        return None, None


# ── RBAC decorators ────────────────────────────────────────────────────────────

def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user, role = get_current_user()
        if not user:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, user=user, role=role, **kwargs)
    return wrapper


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user, role = get_current_user()
        if not user:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        if role != 'admin':
            abort(403)
        return f(*args, user=user, role=role, **kwargs)
    return wrapper


# ── Decrypt user profile helper ────────────────────────────────────────────────

def decrypt_profile(user: dict, password_hash: str) -> dict:
    """Decrypt RSA-encrypted profile fields."""
    try:
        priv = key_manager.recover_rsa_private_key(user, password_hash)
        username = rsa.decrypt(bytes.fromhex(user['username_enc']), priv).decode('utf-8')
        email    = rsa.decrypt(bytes.fromhex(user['email_enc']),    priv).decode('utf-8')
        phone    = rsa.decrypt(bytes.fromhex(user['phone_enc']),    priv).decode('utf-8')
        return {'username': username, 'email': email, 'phone': phone}
    except Exception:
        return {'username': '[decryption error]', 'email': '[error]', 'phone': '[error]'}


def decrypt_post(post: dict, ecc_priv: int) -> dict:
    """Decrypt ECC/ECIES-encrypted post fields."""
    try:
        title   = ecc.decrypt(bytes.fromhex(post['title_enc']),   ecc_priv).decode('utf-8')
        content = ecc.decrypt(bytes.fromhex(post['content_enc']), ecc_priv).decode('utf-8')
        return {**post, 'title': title, 'content': content,
                'integrity_ok': key_manager.verify_post_integrity(post)}
    except Exception as ex:
        return {**post, 'title': '[error]', 'content': f'[decryption error: {ex}]',
                'integrity_ok': False}


# ── Routes: Auth ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    user, role = get_current_user()
    return render_template('index.html', user=user, role=role)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user, role = get_current_user()
    if user:
        return redirect(url_for('feed'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        phone    = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        # Validation
        if not all([username, email, password]):
            flash('All fields are required.', 'error')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html')

        # Hash password
        pw_hash, salt = hash_password(password)

        # Check username not taken (compare hashes)
        uname_hash = sha256(username.lower().encode()).hex()
        if models.get_user_by_username_hash(uname_hash):
            flash('Username already taken.', 'error')
            return render_template('register.html')

        # Generate RSA key pair (for profile encryption)
        rsa_keys = key_manager.generate_rsa_keys(pw_hash)
        rsa_pub = (int(rsa_keys['rsa_pub_e'], 16), int(rsa_keys['rsa_pub_n'], 16))

        # Generate ECC key pair (for post encryption)
        ecc_keys = key_manager.generate_ecc_keys(pw_hash)
        ecc_pub  = ecc.Point(int(ecc_keys['ecc_pub_x'], 16), int(ecc_keys['ecc_pub_y'], 16))

        # Encrypt profile fields with RSA
        username_enc = rsa.encrypt(username.encode(), rsa_pub).hex()
        email_enc    = rsa.encrypt(email.encode(), rsa_pub).hex()
        phone_enc    = rsa.encrypt((phone or 'N/A').encode(), rsa_pub).hex()

        # Generate TOTP secret
        totp_secret = generate_totp_secret()

        # Compute HMAC integrity tag
        hmac_tag = key_manager.compute_user_hmac(0, username_enc, email_enc)

        # Determine role (first user = admin)
        all_users = models.get_all_users()
        role_assigned = 'admin' if len(all_users) == 0 else 'user'

        user_data = {
            'username_enc':  username_enc,
            'email_enc':     email_enc,
            'phone_enc':     phone_enc,
            'username_hash': uname_hash,
            'password_hash': pw_hash,
            'salt':          salt,
            **rsa_keys,
            **ecc_keys,
            'role':          role_assigned,
            'totp_secret':   totp_secret,
            'totp_enabled':  1,
            'hmac_tag':      hmac_tag,
            'created_at':    time.time(),
        }

        user_id = models.create_user(user_data)
        # Update hmac_tag with real user_id
        real_hmac = key_manager.compute_user_hmac(user_id, username_enc, email_enc)
        models.update_user_profile(user_id, username_enc, email_enc, phone_enc, uname_hash, real_hmac)

        models.log_action(user_id, 'REGISTER', f'role={role_assigned}', request.remote_addr)

        # Store TOTP secret in flask session for the setup page
        flask_session['totp_setup_secret'] = totp_secret
        flask_session['totp_setup_uid']    = user_id
        flask_session['totp_setup_user']   = username

        flash('Account created! Set up your 2FA below.', 'success')
        return redirect(url_for('setup_2fa'))

    return render_template('register.html')


@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    secret  = flask_session.get('totp_setup_secret')
    user_id = flask_session.get('totp_setup_uid')
    uname   = flask_session.get('totp_setup_user', 'user')

    if not secret or not user_id:
        return redirect(url_for('login'))

    totp_uri = get_totp_uri(secret, uname)

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if verify_totp(secret, code):
            flask_session.pop('totp_setup_secret', None)
            flask_session.pop('totp_setup_uid', None)
            flask_session.pop('totp_setup_user', None)
            flash('2FA verified! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid code. Try again.', 'error')

    # Current TOTP code for demo display
    current_code = get_totp_code(secret)
    return render_template('setup_2fa.html', secret=secret,
                            totp_uri=totp_uri, current_code=current_code)


@app.route('/login', methods=['GET', 'POST'])
def login():
    user, role = get_current_user()
    if user:
        return redirect(url_for('feed'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        uname_hash = sha256(username.lower().encode()).hex()
        user_row = models.get_user_by_username_hash(uname_hash)

        if not user_row or not verify_password(password, user_row['password_hash'], user_row['salt']):
            models.log_action(None, 'LOGIN_FAIL', f'user={username}', request.remote_addr)
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

        # Store for 2FA step
        flask_session['pending_uid']      = user_row['id']
        flask_session['pending_pw_hash']  = user_row['password_hash']
        flask_session['pending_role']     = user_row['role']

        return redirect(url_for('verify_2fa'))

    return render_template('login.html')


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    uid = flask_session.get('pending_uid')
    if not uid:
        return redirect(url_for('login'))

    user = models.get_user_by_id(uid)
    if not user:
        return redirect(url_for('login'))

    # Current code for demo
    current_code = get_totp_code(user['totp_secret'])

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if verify_totp(user['totp_secret'], code):
            role = flask_session.pop('pending_role', 'user')
            flask_session.pop('pending_uid', None)
            flask_session.pop('pending_pw_hash', None)

            models.log_action(uid, 'LOGIN_SUCCESS', f'role={role}', request.remote_addr)

            resp = make_response(redirect(url_for('feed')))
            set_session(resp, uid, role)
            return resp
        else:
            models.log_action(uid, '2FA_FAIL', '', request.remote_addr)
            flash('Invalid 2FA code. Please try again.', 'error')

    return render_template('verify_2fa.html', current_code=current_code)


@app.route('/logout', methods=['POST'])
def logout():
    user, role = get_current_user()
    if user:
        models.clear_user_session(user['id'])
        models.log_action(user['id'], 'LOGOUT', '', request.remote_addr)

    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie('sg_token')
    return resp


# ── Routes: Feed & Posts ───────────────────────────────────────────────────────

@app.route('/feed')
@require_login
def feed(user, role):
    all_posts = models.get_all_posts()
    decrypted_posts = []

    for post in all_posts:
        post_owner = models.get_user_by_id(post['user_id'])
        if not post_owner:
            continue
        ecc_priv = key_manager.recover_ecc_private_key(post_owner, post_owner['password_hash'])
        dp = decrypt_post(post, ecc_priv)

        # Decrypt post owner's username for display
        rsa_priv = key_manager.recover_rsa_private_key(post_owner, post_owner['password_hash'])
        try:
            owner_name = rsa.decrypt(bytes.fromhex(post_owner['username_enc']), rsa_priv).decode()
        except Exception:
            owner_name = 'Unknown'

        dp['owner_name'] = owner_name
        dp['created_at_fmt'] = time.strftime('%b %d, %Y %H:%M',
                                              time.localtime(post['created_at']))
        decrypted_posts.append(dp)

    return render_template('feed.html', posts=decrypted_posts, user=user, role=role)


@app.route('/posts/new', methods=['GET', 'POST'])
@require_login
def post_new(user, role):
    if request.method == 'POST':
        title   = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()

        if not title or not content:
            flash('Title and content are required.', 'error')
            return render_template('post_new.html', user=user, role=role)

        ecc_pub = key_manager.get_ecc_public_key(user)
        title_enc   = ecc.encrypt(title.encode(), ecc_pub).hex()
        content_enc = ecc.encrypt(content.encode(), ecc_pub).hex()
        hmac_tag    = key_manager.compute_post_hmac(str(user['id']), title_enc, content_enc)
        now = time.time()

        post_id = models.create_post({
            'user_id':     user['id'],
            'title_enc':   title_enc,
            'content_enc': content_enc,
            'hmac_tag':    hmac_tag,
            'created_at':  now,
            'updated_at':  now,
        })

        models.log_action(user['id'], 'CREATE_POST', f'post_id={post_id}', request.remote_addr)
        flash('Post created successfully!', 'success')
        return redirect(url_for('feed'))

    return render_template('post_new.html', user=user, role=role)


@app.route('/posts/<int:post_id>/edit', methods=['GET', 'POST'])
@require_login
def post_edit(user, role, post_id):
    post = models.get_post_by_id(post_id)
    if not post:
        abort(404)
    if post['user_id'] != user['id'] and role != 'admin':
        abort(403)

    ecc_priv = key_manager.recover_ecc_private_key(user, user['password_hash'])
    dp = decrypt_post(post, ecc_priv)

    if request.method == 'POST':
        title   = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()

        if not title or not content:
            flash('Title and content are required.', 'error')
            return render_template('post_edit.html', post=dp, user=user, role=role)

        ecc_pub = key_manager.get_ecc_public_key(user)
        title_enc   = ecc.encrypt(title.encode(), ecc_pub).hex()
        content_enc = ecc.encrypt(content.encode(), ecc_pub).hex()
        hmac_tag    = key_manager.compute_post_hmac(str(user['id']), title_enc, content_enc)

        models.update_post(post_id, title_enc, content_enc, hmac_tag, time.time())
        models.log_action(user['id'], 'EDIT_POST', f'post_id={post_id}', request.remote_addr)
        flash('Post updated!', 'success')
        return redirect(url_for('feed'))

    return render_template('post_edit.html', post=dp, user=user, role=role)


@app.route('/posts/<int:post_id>/delete', methods=['POST'])
@require_login
def post_delete(user, role, post_id):
    post = models.get_post_by_id(post_id)
    if not post:
        abort(404)
    # Only admin or post owner can delete
    if post['user_id'] != user['id'] and role != 'admin':
        abort(403)

    models.delete_post(post_id)
    models.log_action(user['id'], 'DELETE_POST', f'post_id={post_id}', request.remote_addr)
    flash('Post deleted.', 'success')
    return redirect(url_for('feed'))


# ── Routes: Profile ────────────────────────────────────────────────────────────

@app.route('/profile')
@require_login
def profile(user, role):
    profile_data = decrypt_profile(user, user['password_hash'])
    integrity_ok = key_manager.verify_user_integrity(user)
    totp_code = get_totp_code(user['totp_secret'])
    return render_template('profile.html', user=user, role=role,
                            profile=profile_data, integrity_ok=integrity_ok,
                            totp_code=totp_code)


@app.route('/profile/edit', methods=['GET', 'POST'])
@require_login
def profile_edit(user, role):
    profile_data = decrypt_profile(user, user['password_hash'])

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_email    = request.form.get('email', '').strip()
        new_phone    = request.form.get('phone', '').strip()

        if not new_username or not new_email:
            flash('Username and email are required.', 'error')
            return render_template('profile_edit.html', user=user, role=role, profile=profile_data)

        rsa_pub = key_manager.get_rsa_public_key(user)
        uname_hash   = sha256(new_username.lower().encode()).hex()
        username_enc = rsa.encrypt(new_username.encode(), rsa_pub).hex()
        email_enc    = rsa.encrypt(new_email.encode(), rsa_pub).hex()
        phone_enc    = rsa.encrypt((new_phone or 'N/A').encode(), rsa_pub).hex()
        hmac_tag     = key_manager.compute_user_hmac(user['id'], username_enc, email_enc)

        models.update_user_profile(user['id'], username_enc, email_enc,
                                    phone_enc, uname_hash, hmac_tag)
        models.log_action(user['id'], 'EDIT_PROFILE', '', request.remote_addr)
        flash('Profile updated!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile_edit.html', user=user, role=role, profile=profile_data)


# ── Routes: Admin ──────────────────────────────────────────────────────────────

@app.route('/admin/users')
@require_admin
def admin_users(user, role):
    all_users = models.get_all_users()
    decrypted_users = []

    for u in all_users:
        try:
            rsa_priv = key_manager.recover_rsa_private_key(u, u['password_hash'])
            uname = rsa.decrypt(bytes.fromhex(u['username_enc']), rsa_priv).decode()
            email = rsa.decrypt(bytes.fromhex(u['email_enc']), rsa_priv).decode()
            phone = rsa.decrypt(bytes.fromhex(u['phone_enc']), rsa_priv).decode()
        except Exception:
            uname = email = phone = '[error]'

        integrity = key_manager.verify_user_integrity(u)
        joined = time.strftime('%Y-%m-%d', time.localtime(u['created_at']))
        decrypted_users.append({
            **u,
            'username': uname, 'email': email, 'phone': phone,
            'integrity_ok': integrity,
            'joined': joined,
        })

    return render_template('admin/users.html', users=decrypted_users, user=user, role=role)


@app.route('/admin/users/<int:target_id>/role', methods=['POST'])
@require_admin
def admin_set_role(user, role, target_id):
    new_role = request.form.get('role', 'user')
    if new_role not in ('admin', 'user'):
        abort(400)
    models.update_user_role(target_id, new_role)
    models.log_action(user['id'], 'SET_ROLE', f'target={target_id},role={new_role}', request.remote_addr)
    flash(f'Role updated to {new_role}.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/keys')
@require_admin
def admin_keys(user, role):
    all_users = models.get_all_users()
    key_data = []
    for u in all_users:
        try:
            rsa_priv = key_manager.recover_rsa_private_key(u, u['password_hash'])
            uname = rsa.decrypt(bytes.fromhex(u['username_enc']), rsa_priv).decode()
        except Exception:
            uname = '[error]'
        keys = models.get_all_key_versions(u['id'])
        key_data.append({'user': u, 'username': uname, 'keys': keys})

    return render_template('admin/keys.html', key_data=key_data, user=user, role=role)


@app.route('/admin/keys/<int:target_id>/rotate', methods=['POST'])
@require_admin
def admin_rotate_keys(user, role, target_id):
    target_user = models.get_user_by_id(target_id)
    if not target_user:
        abort(404)
    try:
        key_manager.rotate_keys_for_user(target_id, target_user['password_hash'])
        models.log_action(user['id'], 'ROTATE_KEYS', f'target={target_id}', request.remote_addr)
        flash(f'Keys rotated for user #{target_id}.', 'success')
    except Exception as ex:
        flash(f'Key rotation failed: {ex}', 'error')
    return redirect(url_for('admin_keys'))


@app.route('/admin/logs')
@require_admin
def admin_logs(user, role):
    logs = models.get_audit_logs(limit=300)
    for log in logs:
        log['ts_fmt'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log['ts']))
    return render_template('admin/logs.html', logs=logs, user=user, role=role)


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    user, role = get_current_user()
    return render_template('error.html', code=403,
                            message="Access Denied — You don't have permission to view this page.",
                            user=user, role=role), 403


@app.errorhandler(404)
def not_found(e):
    user, role = get_current_user()
    return render_template('error.html', code=404,
                            message="Page not found.",
                            user=user, role=role), 404


# ── Bootstrap ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    models.init_db()
    print("=" * 60)
    print("  SOVEREIGN GUARD — Secure System")
    print("  RSA-2048 + ECC P-256 | HMAC-SHA256 | TOTP 2FA")
    print("  All algorithms implemented from scratch")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
