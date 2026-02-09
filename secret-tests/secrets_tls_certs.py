# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# SECRET: TLS/SSL certificates with private keys, PKCS12
# ============================================================================
from flask import Flask, jsonify
import ssl

app = Flask(__name__)

# ── REACHABLE: TLS private key embedded in code ─────────────────────────
TLS_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7EXAMPLEaBcDe
FgHiJkLmNoPqRsTuVwXyZ01234567890EXAMPLE1234567890abcdefghijklmnopqr
stuvwxyzEXAMPLE1234567890abcdefghijklmnopqrstuvwxyzEXAMPLE1234567890
-----END PRIVATE KEY-----"""

TLS_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJV
UzELMAkGA1UECBMCQ0ExEXAMPLE1234567890abcdefghijklmnopqrstuvwxyzEXA
-----END CERTIFICATE-----"""

# ── REACHABLE: PFX/PKCS12 password ─────────────────────────────────────
PKCS12_PASSWORD = "Pr0d_C3rt_P@ssw0rd_2024!"
PKCS12_PATH = "/etc/ssl/private/prod-api.pfx"

# ── REACHABLE: mTLS client cert and key paths with passwords ───────────
MTLS_CONFIG = {
    "client_cert": "/etc/ssl/client.pem",
    "client_key": "/etc/ssl/client-key.pem",
    "key_password": "mTLS_K3y_P@ss!",
    "ca_cert": "/etc/ssl/ca.pem",
}

@app.route('/api/tls/info', methods=['GET'])
def tls_info():
    return jsonify({'cert_cn': 'api.example.com', 'key_type': 'RSA-2048'})

@app.route('/api/mtls/connect', methods=['POST'])
def mtls_connect():
    ctx = ssl.create_default_context()
    ctx.load_cert_chain(MTLS_CONFIG['client_cert'], MTLS_CONFIG['client_key'],
                         password=MTLS_CONFIG['key_password'])
    return jsonify({'connected': True})

def _dead_cert():
    EXPIRED_KEY = "-----BEGIN PRIVATE KEY-----\nDEADBEEFEXPIRED\n-----END PRIVATE KEY-----"
    return EXPIRED_KEY

if __name__ == '__main__':
    app.run(port=6008)
