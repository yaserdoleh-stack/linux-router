"""Local password authentication for Router Manager (standard library only)."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

AUTH_FILE = Path('/var/lib/router-manager/auth.json')
COOKIE = 'router_manager_session'
TTL = 8 * 3600
ITERATIONS = 600_000


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _unb64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def read_auth():
    if not AUTH_FILE.is_file():
        return None
    data = json.loads(AUTH_FILE.read_text())
    if not all(k in data for k in ('salt', 'hash', 'secret')):
        raise RuntimeError('Invalid auth.json; run setup-admin.py')
    return data


def set_password(password):
    if len(password) < 12:
        raise ValueError('Password must contain at least 12 characters')
    salt = secrets.token_bytes(24)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(AUTH_FILE.parent, 0o700)
    tmp = AUTH_FILE.with_suffix('.tmp')
    with tmp.open('w') as fp:
        os.fchmod(fp.fileno(), 0o600)
        json.dump({'salt': _b64(salt), 'hash': _b64(hashed),
                   'secret': _b64(secrets.token_bytes(32)), 'iterations': ITERATIONS}, fp)
    os.replace(tmp, AUTH_FILE)


def verify_password(password):
    data = read_auth()
    if not data or not isinstance(password, str):
        return False
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), _unb64(data['salt']), data['iterations'])
    return hmac.compare_digest(digest, _unb64(data['hash']))


def issue_session():
    data = read_auth()
    payload = f'admin:{int(time.time()) + TTL}:{secrets.token_hex(12)}'
    signature = hmac.new(_unb64(data['secret']), payload.encode(), hashlib.sha256).digest()
    return _b64(payload.encode()) + '.' + _b64(signature)


def valid_session(cookie):
    try:
        payload_b64, signature_b64 = cookie.split('.', 1)
        payload = _unb64(payload_b64)
        expected = hmac.new(_unb64(read_auth()['secret']), payload, hashlib.sha256).digest()
        parts = payload.decode().split(':')
        return hmac.compare_digest(expected, _unb64(signature_b64)) and parts[0] == 'admin' and int(parts[1]) >= time.time()
    except (ValueError, TypeError, AttributeError, KeyError, OSError):
        return False
