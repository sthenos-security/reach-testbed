# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Triggers: Semgrep weak-hash, insecure-cipher, hardcoded-key, weak-random
# CWE-327 (Broken Crypto), CWE-328 (Weak Hash), CWE-330 (Weak PRNG)
# CWE-798 (Hardcoded Credentials in Crypto)
# ============================================================================
"""
Cryptographic weaknesses: weak hashing, broken ciphers, insecure randomness.
"""
from flask import Flask, request, jsonify
import hashlib
import hmac
import random
import string

app = Flask(__name__)


# ============================================================================
# REACHABLE: CWE-328 — Weak Hash (MD5 for passwords)
# ============================================================================
@app.route('/api/auth/register', methods=['POST'])
def register():
    """MD5 for password hashing — trivially reversible."""
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    # BAD: MD5 is not suitable for password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    return jsonify({'user': username, 'hash': password_hash})


# REACHABLE: CWE-328 — Weak Hash (SHA1 for integrity)
@app.route('/api/files/checksum', methods=['POST'])
def file_checksum():
    """SHA1 for file integrity — collision attacks feasible."""
    data = request.get_data()
    # BAD: SHA1 is collision-prone (SHAttered attack, 2017)
    checksum = hashlib.sha1(data).hexdigest()
    return jsonify({'sha1': checksum})


# ============================================================================
# REACHABLE: CWE-327 — Broken Crypto Algorithm
# ============================================================================
@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    """DES encryption — 56-bit key, brute-forceable."""
    from Crypto.Cipher import DES
    plaintext = request.json.get('data', '').encode()
    # BAD: DES is broken — 56-bit key
    key = b'8byteky'  # DES requires 8-byte key
    key = key.ljust(8, b'\0')
    cipher = DES.new(key, DES.MODE_ECB)
    # BAD: ECB mode leaks patterns
    padded = plaintext.ljust((len(plaintext) // 8 + 1) * 8, b'\0')
    encrypted = cipher.encrypt(padded)
    return jsonify({'ciphertext': encrypted.hex()})


# REACHABLE: CWE-327 — AES-ECB (pattern leaking)
@app.route('/api/encrypt/aes', methods=['POST'])
def encrypt_aes_ecb():
    """AES-ECB leaks plaintext patterns."""
    from Crypto.Cipher import AES
    plaintext = request.json.get('data', '').encode()
    # BAD: ECB mode — identical plaintext blocks produce identical ciphertext
    key = b'0123456789abcdef'  # Hardcoded AES key
    cipher = AES.new(key, AES.MODE_ECB)
    padded = plaintext.ljust((len(plaintext) // 16 + 1) * 16, b'\0')
    encrypted = cipher.encrypt(padded)
    return jsonify({'ciphertext': encrypted.hex()})


# ============================================================================
# REACHABLE: CWE-330 — Weak PRNG for security-sensitive operations
# ============================================================================
@app.route('/api/token/generate', methods=['GET'])
def generate_token():
    """random.choice for auth tokens — predictable PRNG."""
    # BAD: random module is not cryptographically secure
    token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
    return jsonify({'token': token})


@app.route('/api/otp/generate', methods=['GET'])
def generate_otp():
    """random.randint for OTP — predictable."""
    # BAD: Predictable OTP generation
    otp = random.randint(100000, 999999)
    return jsonify({'otp': otp})


# REACHABLE: CWE-330 — Weak random for session ID
@app.route('/api/session/create', methods=['POST'])
def create_session():
    """Predictable session ID using random module."""
    # BAD: Session IDs must use CSPRNG
    session_id = hex(random.getrandbits(128))[2:]
    return jsonify({'session_id': session_id})


# ============================================================================
# REACHABLE: CWE-798 — Hardcoded Cryptographic Key
# ============================================================================
HMAC_SECRET = b"super-secret-hmac-key-never-rotate"  # Hardcoded HMAC key

@app.route('/api/sign', methods=['POST'])
def sign_data():
    """HMAC with hardcoded key."""
    data = request.json.get('data', '').encode()
    # Uses hardcoded key above
    signature = hmac.new(HMAC_SECRET, data, hashlib.sha256).hexdigest()
    return jsonify({'signature': signature})


# ============================================================================
# UNREACHABLE: Same patterns in dead code
# ============================================================================
def _dead_md5_hash():
    """UNREACHABLE — dead code MD5."""
    return hashlib.md5(b"password123").hexdigest()

def _dead_weak_random():
    """UNREACHABLE — dead code weak random."""
    return random.randint(0, 99999)

def _dead_des_encrypt():
    """UNREACHABLE — dead code DES."""
    from Crypto.Cipher import DES
    cipher = DES.new(b'deadkey!', DES.MODE_ECB)
    return cipher.encrypt(b'deaddata')


if __name__ == '__main__':
    app.run(port=5003)
