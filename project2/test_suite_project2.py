#I used DeepSeek AI to complete this test file.

import pytest
import requests
import sqlite3
import base64
import jwt
import threading
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from main import MyServer, hostName, serverPort, int_to_base64
from http.server import BaseHTTPRequestHandler, HTTPServer

@pytest.fixture(scope="module")
def test_server():
    # Setup database and server
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS keys')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    
    now = datetime.now()
    valid_exp = int((now + timedelta(hours=1)).timestamp())
    expired_exp = int((now - timedelta(hours=1)).timestamp())
    
    # Generate keys (matches main.py's implementation)
    valid_key = rsa.generate_private_key(65537, 2048)
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    expired_key = rsa.generate_private_key(65537, 2048)
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (valid_pem, valid_exp))
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (expired_pem, expired_exp))
    conn.commit()
    conn.close()
    
    # Starts the server
    server = HTTPServer((hostName, serverPort), MyServer)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    time.sleep(0.2)  # Makes sure the server starts
    
    yield
    
    # Teardown
    server.shutdown()
    server.server_close()
    thread.join()
    time.sleep(0.1)

@pytest.mark.parametrize("value,expected", [
    (0x1, "AQ"),        
    (0x123, "ASM"),     
    (0xabcdef, "q83v"), 
    (65537, "AQAB"),    
])
def test_int_to_base64(value, expected):
    assert int_to_base64(value) == expected

def test_jwks_endpoint(test_server):
    response = requests.get(f'http://{hostName}:{serverPort}/.well-known/jwks.json')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json'
    
    jwks = response.json()
    assert len(jwks['keys']) == 1  # Only valid key should be present here
    
    key = jwks['keys'][0]
    assert key['kid'] == '1'
    assert key['alg'] == 'RS256'
    assert key['kty'] == 'RSA'
    assert key['use'] == 'sig'
    assert all(k in key for k in ['n', 'e'])

def test_valid_auth_flow(test_server):
    # Tests without expired parameter
    response = requests.post(f'http://{hostName}:{serverPort}/auth')
    assert response.status_code == 200
    token = response.text
    
    # Verifies token headers
    header = jwt.get_unverified_header(token)
    assert header['alg'] == 'RS256'
    assert header['kid'] == '1'
    
    # Verifies token contents
    jwks = requests.get(f'http://{hostName}:{serverPort}/.well-known/jwks.json').json()
    jwk = jwks['keys'][0]
    public_key = rsa.RSAPublicNumbers(
        e=int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '==')), 
        n=int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='))
    ).public_key()
    
    decoded = jwt.decode(token, public_key, algorithms=['RS256'])
    assert decoded['user'] == 'username'
    assert decoded['exp'] > datetime.now().timestamp()

def test_expired_auth_flow(test_server):
    # Tests with expired parameter
    response = requests.post(f'http://{hostName}:{serverPort}/auth?expired=true')
    assert response.status_code == 200
    token = response.text
    
    # Verifies token headers
    header = jwt.get_unverified_header(token)
    assert header['kid'] == '2'
    
    # Verifies token contents
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('SELECT key FROM keys WHERE kid=2')
    expired_pem = cursor.fetchone()[0]
    private_key = serialization.load_pem_private_key(expired_pem, None)
    decoded = jwt.decode(token, private_key.public_key(), algorithms=['RS256'])
    assert decoded['exp'] < datetime.now().timestamp()

@pytest.mark.parametrize("method", ['PUT', 'DELETE', 'PATCH', 'HEAD'])
def test_unsupported_methods(test_server, method):
    response = requests.request(method, f'http://{hostName}:{serverPort}/auth')
    assert response.status_code == 405

def test_invalid_path_handling(test_server):
    # Tests GET in a invalid path
    response = requests.get(f'http://{hostName}:{serverPort}/invalid')
    assert response.status_code == 405
    
    # Tests POST in a invalid path
    response = requests.post(f'http://{hostName}:{serverPort}/invalid')
    assert response.status_code == 405

def test_malformed_expired_param(test_server):
    # Tests the code with different expired parameter values
    response = requests.post(f'http://{hostName}:{serverPort}/auth?expired=maybe')
    assert response.status_code == 200  

def test_no_valid_keys_scenario(test_server):
    # Expires all keys
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    conn.execute('UPDATE keys SET exp=?', (int((datetime.now() - timedelta(hours=2)).timestamp()),))
    conn.commit()
    conn.close()
    
    response = requests.post(f'http://{hostName}:{serverPort}/auth')
    assert response.status_code == 404

def test_database_schema(test_server):
    # Verifies the table structure
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(keys)")
    columns = {info[1]: info[2] for info in cursor.fetchall()}
    
    assert columns == {
        'kid': 'INTEGER',
        'key': 'BLOB',
        'exp': 'INTEGER'
    }
    conn.close()
