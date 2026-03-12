# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Triggers: Semgrep secrets-in-config, hardcoded-password, dotenv-secrets
# Tests secrets in config files, .env patterns, YAML/JSON configs
# ============================================================================
"""
Secrets in configuration patterns — environment files, YAML, JSON, .env
"""
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# .env-style secrets loaded directly (BAD — should use vault/secrets manager)
DATABASE_PASSWORD = os.getenv("DB_PASSWORD", "FallbackPassword123!")  # Default = secret leak
REDIS_PASSWORD = os.getenv("REDIS_PASS", "r3d1s_p@ssword!")
ADMIN_PASSWORD = "admin:SuperSecretAdmin2024!"

# Hardcoded basic auth
BASIC_AUTH_USER = "admin"
BASIC_AUTH_PASS = "P@ssw0rd!2024"

# API keys in variables that look like config
config = {
    "api_key": "abcdef0123456789abcdef0123456789",
    "secret_key": "sk_test_abcdef0123456789abcdef",
    "database_url": "postgresql://app:Pr0duct10n!@db.internal:5432/main",
    "redis_url": "redis://:R3d1sP@ss@cache.internal:6379",
    "smtp_password": "smtp_password_never_in_code",
    "encryption_key": "aes-256-key-0123456789abcdef0123456789abcdef",
}


@app.route('/api/config', methods=['GET'])
def get_config():
    """Accidentally exposes config with secrets."""
    return jsonify(config)

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Hardcoded basic auth."""
    user = request.json.get('username', '')
    passwd = request.json.get('password', '')
    if user == BASIC_AUTH_USER and passwd == BASIC_AUTH_PASS:
        return jsonify({'status': 'authenticated', 'role': 'admin'})
    return jsonify({'status': 'denied'}), 401

@app.route('/api/db/connect', methods=['GET'])
def db_connect():
    """Uses config dict with embedded password."""
    import psycopg2
    conn = psycopg2.connect(config['database_url'])
    return jsonify({'connected': True})

@app.route('/api/cache/flush', methods=['POST'])
def flush_cache():
    """Redis connection with hardcoded password."""
    import redis
    r = redis.from_url(config['redis_url'])
    r.flushall()
    return jsonify({'flushed': True})

@app.route('/api/email/send', methods=['POST'])
def send_email():
    """SMTP with hardcoded password."""
    import smtplib
    server = smtplib.SMTP('smtp.example.com', 587)
    server.login('noreply@example.com', config['smtp_password'])
    return jsonify({'sent': True})


# UNREACHABLE config secrets
_dead_config = {
    "old_api_key": "REVOKED-key-0123456789",
    "old_db_url": "postgresql://old_admin:OldP@ss@retired-db:5432/legacy",
}

def _dead_config_usage():
    import psycopg2
    psycopg2.connect(_dead_config['old_db_url'])


if __name__ == '__main__':
    app.run(port=5011)
