from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
from datetime import datetime, timezone, timedelta

import sqlite3 

hostName = "localhost"
serverPort = 8080

#Converts an integer to a Base64URL-encoded string 
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            #Connects to the Sqlite database file
            conn = sqlite3.connect('totally_not_my_privateKeys.db')
            cursor = conn.cursor()
            
            now = (datetime.now())

            valid_exp = int((now + timedelta(hours = 1)).timestamp()) # expire in 1 hour
            expired_exp = int((now - timedelta(hours = 1)).timestamp()) # expire now

            #Checks if "expired" query parameter is present
            if 'expired' in params:
                cursor.execute('SELECT kid, key, exp FROM keys WHERE exp <= ?', (now.timestamp(),))
                                
            #Checks if "expired" query parameter is not present
            else:
                cursor.execute('SELECT kid, key, exp FROM keys WHERE exp > ? ', (now.timestamp(),))
                                
            key_row = cursor.fetchone()
            conn.close()

            if not key_row:
                self.send_response(404)
                self.end_headers()
                return
            #Serializes keys
            kid, key_pem, exp = key_row
            private_key = serialization.load_pem_private_key(
                key_pem,
                password = None,
            )
            headers = {
                "kid": str(kid)
            }
            token_payload = {"user": "username", "exp": exp}

            #Signs a JWT with private key 
            
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return #returns the JWT
        

        self.send_response(405)
        self.end_headers()
        

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            #Connects to the Sqlite database file
            conn = sqlite3.connect('totally_not_my_privateKeys.db')
            cursor = conn.cursor()
            now = (datetime.now())

            #Reads all non-expired private keys
            cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (now.timestamp(),))
            valid_keys = cursor.fetchall()
            conn.close()

            jwks_keys = [] 
            for kid, key_pem in valid_keys:
                private_key = serialization.load_pem_private_key(
                    key_pem, 
                    password = None
                )

                public_numbers = private_key.public_key().public_numbers()
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e)
                })
            
            #Creates a JWKS response from private keys
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"keys": jwks_keys}), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    #Creates SQLite3 database and table schema
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')

    now = (datetime.now())

    valid_exp = int((now + timedelta(hours = 1)).timestamp()) # expire in 1 hour
    expired_exp = int((now - timedelta(hours = 1)).timestamp()) # expire now

    #Generates keys
    valid_key = rsa.generate_private_key( # Creates the key expire in 1 hour
        public_exponent=65537,
        key_size= 2048
    )
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    expired_key = rsa.generate_private_key( # Creates the expired key
        public_exponent=65537,
        key_size=2048
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (valid_pem, valid_exp))
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (expired_pem, expired_exp))
    conn.commit()
    conn.close()

    # Starts server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
