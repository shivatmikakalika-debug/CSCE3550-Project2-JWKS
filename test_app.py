"""Functional tests for the SQLite-backed JWKS service."""
import base64
import json
import sqlite3
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

import app as server


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(server, 'DB_PATH', tmp_path / 'totally_not_my_privateKeys.db')
    server.initialize_db()
    with server.app.test_client() as client:
        yield client


def test_database_schema_and_key_types(client):
    with server.connect_db() as conn:
        columns = conn.execute('PRAGMA table_info(keys)').fetchall()
        rows = conn.execute('SELECT kid, key, exp FROM keys').fetchall()
    assert [column['name'] for column in columns] == ['kid', 'key', 'exp']
    assert len(rows) >= 2
    assert all(isinstance(row['kid'], int) for row in rows)
    assert all(isinstance(row['key'], bytes) for row in rows)
    assert any(row['exp'] > time.time() for row in rows)
    assert any(row['exp'] <= time.time() for row in rows)


def test_jwks_only_valid_keys(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    keys = response.get_json()['keys']
    assert keys
    assert all(set(('kid', 'kty', 'alg', 'n', 'e')).issubset(key) for key in keys)
    with server.connect_db() as conn:
        expired = {str(row['kid']) for row in conn.execute('SELECT kid FROM keys WHERE exp <= ?', (int(time.time()),))}
    assert not any(key['kid'] in expired for key in keys)


def test_auth_valid_token_verifies_against_jwks(client):
    token = client.post('/auth', json={'username': 'userABC', 'password': 'password123'}).get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    jwks = client.get('/.well-known/jwks.json').get_json()['keys']
    matching = next(key for key in jwks if key['kid'] == header['kid'])
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(matching))
    claims = jwt.decode(token, public_key, algorithms=['RS256'])
    assert claims['sub'] == 'fake-user'


def test_auth_expired_token(client):
    token = client.post('/auth?expired=true', headers={'Authorization': 'Basic dXNlcjpwYXNz'}).get_data(as_text=True)
    claims = jwt.decode(token, options={'verify_signature': False, 'verify_exp': False})
    assert claims['exp'] <= time.time()
    assert jwt.get_unverified_header(token)['kid']


def test_persistence_across_initialization(client):
    with server.connect_db() as conn:
        before = conn.execute('SELECT COUNT(*) FROM keys').fetchone()[0]
    server.initialize_db()
    with server.connect_db() as conn:
        after = conn.execute('SELECT COUNT(*) FROM keys').fetchone()[0]
    assert before == after


def test_missing_key_returns_503(client):
    with server.connect_db() as conn:
        conn.execute('DELETE FROM keys')
    assert client.post('/auth').status_code == 503
    assert client.post('/auth?expired').status_code == 503
    assert client.get('/.well-known/jwks.json').get_json() == {'keys': []}


def test_key_generation_and_base64url(client):
    with server.connect_db() as conn:
        server.save_key(conn, int(time.time()) + 5000)
        row = conn.execute('SELECT kid, key, exp FROM keys ORDER BY kid DESC LIMIT 1').fetchone()
    key = serialization.load_pem_private_key(row['key'], password=None)
    assert key.key_size == 2048
    assert server.create_jwk(row)['kid'] == str(row['kid'])
    assert server.base64url(65537) == 'AQAB'
    assert server.base64url(0) == 'AA'
