# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# SECRET: RSA Private Keys, JWT Secrets, SSH Keys
# ============================================================================
from flask import Flask, request, jsonify
import jwt as pyjwt

app = Flask(__name__)

# ── REACHABLE: RSA Private Key (PEM) ────────────────────────────────────
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2Z3qX2BTLS4e5eSGATr2hANfJn1rGiQmgOKoBSPHPO1nnGBL
EXAMPLEr2hANfJn1rGiQmgOKoBSPHPO1nnGBLEXAMPLEr2hANfJn1rGiQmgOKoBS
PHPxO1nnGBLEXAMPLE9K2Z3qX2BTLS4e5eSGATr2hANfJn1rGiQmgOKoBSPHPO1n
nGBLEXAMPLEr2hANfJn1rGiQmgOKoBSPHPO1nnGBLEXAMPLEr2hANfJn1rGiQmgO
KoBSPHPO1nnGBLEXAMPLE2Z3qX2BTLS4e5eSGATr2hANfJn1rGiQmgOKoBSPHPO1
-----END RSA PRIVATE KEY-----"""

# ── REACHABLE: EC Private Key ───────────────────────────────────────────
EC_PRIVATE_KEY = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVDGiAEMPsJb/QB6poAcGBSuBBAAi
oWQDYgAEY1GlPyRPrzIhFMA6EXAMPLE1234567890abcdefEXAMPLE1234567890ab
-----END EC PRIVATE KEY-----"""

# ── REACHABLE: JWT HMAC Secret ──────────────────────────────────────────
JWT_SECRET = "my-super-secret-jwt-signing-key-never-commit-this-2024!"

# ── REACHABLE: SSH Private Key ──────────────────────────────────────────
SSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBiT0EXAMPLE1234567890abcdefEXAMPLE1234567890abcdefEXAMPLE
AAAAQ0EXAMPLE1234567890abcdefghijklmnopqrstuvwxyzEXAMPLE1234567890abcd
-----END OPENSSH PRIVATE KEY-----"""

@app.route('/api/jwt/sign', methods=['POST'])
def sign_jwt():
    payload = request.json.get('payload', {})
    token = pyjwt.encode(payload, RSA_PRIVATE_KEY, algorithm='RS256')
    return jsonify({'token': token})

@app.route('/api/jwt/sign-hmac', methods=['POST'])
def sign_hmac():
    payload = request.json.get('payload', {})
    token = pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token})

@app.route('/api/ssh/connect', methods=['POST'])
def ssh_connect():
    return jsonify({'key_fingerprint': 'SHA256:EXAMPLE', 'key_type': 'ed25519'})

def _dead_keys():
    REVOKED_KEY = "-----BEGIN RSA PRIVATE KEY-----\nDEADBEEF\n-----END RSA PRIVATE KEY-----"
    return REVOKED_KEY

if __name__ == '__main__':
    app.run(port=6005)
