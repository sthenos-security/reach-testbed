# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Tests: Semgrep secrets detection — AWS, GCP, Azure, Generic API keys
# All credentials below are FAKE/REVOKED patterns that match detection rules
# ============================================================================
"""
Secrets tests: REACHABLE (used in active code paths) and UNREACHABLE (dead code).
Each secret type is tested with both patterns.
"""
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================================
# REACHABLE SECRETS — Used in active routes
# ============================================================================

# AWS credentials (AKIA pattern)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_SESSION_TOKEN = "FwoGZXIvYXdzEBYaDHqa0AP1z0Ab3kfMbyLIAdnGhBQnsMpi/L+Fa+EXAMPLE"

# GCP service account key (JSON key pattern)
GCP_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuvw"
GCP_SERVICE_ACCOUNT_KEY = '{"type":"service_account","project_id":"test-project","private_key_id":"key123","private_key":"-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB6KiFAExAMPLEKEY\\n-----END RSA PRIVATE KEY-----\\n","client_email":"test@test-project.iam.gserviceaccount.com"}'

# Azure credentials
AZURE_CLIENT_SECRET = "azc.ABCdef123456789-EXAMPLE_SECRET_VALUE"
AZURE_STORAGE_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/ABCDEFGHIJKLMNOPQRSTUV=="

# Stripe keys
STRIPE_SECRET_KEY = "sk_live_51234567890abcdefghijklmnopqrstuvwxyz"
STRIPE_PUBLISHABLE_KEY = "pk_live_51234567890abcdefghijklmnopqrstuvwxyz"

# GitHub token (classic PAT pattern)
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
GITHUB_OAUTH_SECRET = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"

# Slack tokens
SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# SendGrid API key
SENDGRID_API_KEY = "SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV"

# Twilio credentials
TWILIO_ACCOUNT_SID = "AC1234567890abcdef1234567890abcdef"
TWILIO_AUTH_TOKEN = "1234567890abcdef1234567890abcdef"

# Database connection strings
DATABASE_URL = "postgresql://admin:SuperS3cretP@ss!@db.example.com:5432/production"
MONGODB_URI = "mongodb+srv://admin:P@ssw0rd123@cluster0.mongodb.net/mydb"
REDIS_URL = "redis://:s3cretRedisP@ss@redis.example.com:6379/0"
MYSQL_DSN = "mysql://root:r00tP@ssw0rd@mysql.example.com:3306/app"

# JWT / Generic secrets
JWT_SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB6KiEXAMPLEKEY\n-----END RSA PRIVATE KEY-----"
HMAC_SECRET = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

# Mailgun
MAILGUN_API_KEY = "key-1234567890abcdef1234567890abcdef"

# Datadog
DATADOG_API_KEY = "abcdef1234567890abcdef1234567890ab"
DATADOG_APP_KEY = "abcdef1234567890abcdef1234567890abcdef12"

# OpenAI
OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"

# Anthropic
ANTHROPIC_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH"


# ============================================================================
# REACHABLE: Routes that USE the secrets above
# ============================================================================
@app.route('/api/aws/list-buckets')
def list_buckets():
    import boto3
    client = boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    return jsonify({'buckets': str(client.list_buckets())})

@app.route('/api/stripe/charge', methods=['POST'])
def create_charge():
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    return jsonify({'key_prefix': STRIPE_SECRET_KEY[:10]})

@app.route('/api/slack/send', methods=['POST'])
def send_slack():
    import requests
    msg = request.json.get('message', 'test')
    requests.post(SLACK_WEBHOOK_URL, json={'text': msg})
    return jsonify({'sent': True})

@app.route('/api/github/repos')
def list_repos():
    import requests
    resp = requests.get('https://api.github.com/user/repos',
        headers={'Authorization': f'token {GITHUB_TOKEN}'})
    return jsonify({'repos': resp.json()})

@app.route('/api/email/send', methods=['POST'])
def send_email():
    import requests
    requests.post('https://api.mailgun.net/v3/example.com/messages',
        auth=('api', MAILGUN_API_KEY),
        data={'from': 'test@test.com', 'to': 'user@test.com', 'text': 'test'})
    return jsonify({'sent': True})

@app.route('/api/db/connect')
def db_connect():
    import psycopg2
    conn = psycopg2.connect(DATABASE_URL)
    return jsonify({'connected': True})

@app.route('/api/openai/complete', methods=['POST'])
def openai_complete():
    import openai
    openai.api_key = OPENAI_API_KEY
    return jsonify({'key_set': True})

@app.route('/api/gcp/translate', methods=['POST'])
def gcp_translate():
    import requests
    text = request.json.get('text', '')
    requests.post(f'https://translation.googleapis.com/language/translate/v2?key={GCP_API_KEY}',
        json={'q': text, 'target': 'es'})
    return jsonify({'translated': True})

@app.route('/api/datadog/metric', methods=['POST'])
def send_metric():
    import requests
    requests.post('https://api.datadoghq.com/api/v1/series',
        headers={'DD-API-KEY': DATADOG_API_KEY},
        json={'series': [{'metric': 'test', 'points': [[0, 1]]}]})
    return jsonify({'sent': True})


# ============================================================================
# UNREACHABLE: Secrets in dead code paths
# ============================================================================
def _dead_aws():
    """Never called — AWS creds in dead code."""
    OLD_AWS_KEY = "AKIAI44QH8DHBEXAMPLE"
    OLD_AWS_SECRET = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
    import boto3
    boto3.client('s3', aws_access_key_id=OLD_AWS_KEY, aws_secret_access_key=OLD_AWS_SECRET)

def _dead_stripe():
    """Never called — dead Stripe key."""
    REVOKED_KEY = "sk_live_REVOKED_abcdefghijklmnopqrstuvwxyz"
    return REVOKED_KEY

def _dead_private_key():
    """Never called — private key in dead code."""
    PEM = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIODyqN7M6oG3RIIChVYbJK0PaUGGw/HbEXAMPLEKEY
-----END EC PRIVATE KEY-----"""
    return PEM

def _dead_db_creds():
    """Never called — DB creds in dead function."""
    return "postgresql://legacy_admin:0ldP@ss!@old-db.internal:5432/legacy"

def _dead_jwt_secret():
    """Never called — JWT in dead code."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EXAMPLE_DEAD_TOKEN"


if __name__ == '__main__':
    app.run(port=5010)
