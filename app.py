"""SQLite-backed JWKS server for CSCE 3550 Project 2."""
import base64
import sqlite3
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = Path('totally_not_my_privateKeys.db')


def connect_db():
    """Connect to the local SQLite file with row names enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def save_key(conn, expires_at):
    """Generate an RSA key and save its PEM representation safely."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    conn.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, expires_at))


def initialize_db():
    """Initialize schema and ensure at least one valid and expired key exist."""
    now = int(time.time())
    with connect_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )''')
        if conn.execute('SELECT 1 FROM keys WHERE exp > ? LIMIT 1', (now,)).fetchone() is None:
            save_key(conn, now + 7200)
        if conn.execute('SELECT 1 FROM keys WHERE exp <= ? LIMIT 1', (now,)).fetchone() is None:
            save_key(conn, now - 3600)


def base64url(number):
    """Encode an RSA integer as an unpadded base64url string."""
    data = number.to_bytes(max(1, (number.bit_length() + 7) // 8), 'big')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def create_jwk(row):
    """Expose only the public part of a stored RSA private key."""
    private_key = serialization.load_pem_private_key(row['key'], password=None)
    numbers = private_key.public_key().public_numbers()
    return {
        'kty': 'RSA', 'kid': str(row['kid']), 'use': 'sig', 'alg': 'RS256',
        'n': base64url(numbers.n), 'e': base64url(numbers.e),
    }


@app.get('/.well-known/jwks.json')
def jwks():
    """List the public keys of all currently unexpired records."""
    with connect_db() as conn:
        rows = conn.execute('SELECT kid, key, exp FROM keys WHERE exp > ?',
                            (int(time.time()),)).fetchall()
    return jsonify({'keys': [create_jwk(row) for row in rows]})


@app.post('/auth')
def auth():
    """Mock authentication and sign a JWT with a stored key."""
    now = int(time.time())
    is_expired = 'expired' in request.args
    operator = '<=' if is_expired else '>'
    with connect_db() as conn:
        # Only a fixed, internally selected operator is interpolated.
        row = conn.execute(
            f'SELECT kid, key, exp FROM keys WHERE exp {operator} ? ORDER BY kid DESC LIMIT 1',
            (now,),
        ).fetchone()
    if row is None:
        return jsonify({'error': 'No matching signing key'}), 503
    private_key = serialization.load_pem_private_key(row['key'], password=None)
    payload = {
        'sub': 'fake-user', 'iat': now,
        'exp': int(row['exp']) if is_expired else min(now + 3600, int(row['exp'])),
    }
    token = jwt.encode(payload, private_key, algorithm='RS256',
                       headers={'kid': str(row['kid'])})
    return token, 200, {'Content-Type': 'text/plain'}


initialize_db()

if __name__ == '__main__':
    app.run(port=8080)
