# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Triggers: Semgrep secrets rules for AWS, GCP, Azure, Stripe, GitHub, etc.
# ALL KEYS ARE FAKE/EXAMPLE PATTERNS — they match regex but are not valid.
# ============================================================================
"""
Comprehensive secrets detection testbed — REACHABLE variants.
Each secret is used in a Flask route (reachable from entrypoint).
"""
from flask import Flask, request, jsonify
import boto3
import requests

app = Flask(__name__)

# ============================================================================
# AWS Credentials (multiple patterns)
# ============================================================================
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_SESSION_TOKEN = "FwoGZXIvYXdzEBYaDHqa0BEXAMPLETOKEN/EXAMPLE/SESSION/TOKEN+PADDING=="

@app.route('/api/aws/s3/list', methods=['GET'])
def list_s3_buckets():
    client = boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        aws_session_token=AWS_SESSION_TOKEN,
    )
    return jsonify({'buckets': []})

# ============================================================================
# GCP Service Account Key
# ============================================================================
GCP_SERVICE_KEY = {
    "type": "service_account",
    "project_id": "testbed-project-123",
    "private_key_id": "key123abc456def789",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoSo0EXAMPLE\n-----END RSA PRIVATE KEY-----\n",
    "client_email": "test@testbed-project-123.iam.gserviceaccount.com",
    "client_id": "123456789012345678901",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
}

@app.route('/api/gcp/storage', methods=['GET'])
def gcp_storage():
    return jsonify({'key_project': GCP_SERVICE_KEY['project_id']})

# ============================================================================
# Azure Credentials
# ============================================================================
AZURE_CLIENT_ID = "12345678-1234-1234-1234-123456789abc"
AZURE_CLIENT_SECRET = "abc8Q~EXAMPLE_SECRET_VALUE.xYzAbCdEfGhIjKlMnOp"
AZURE_TENANT_ID = "87654321-4321-4321-4321-cba987654321"
AZURE_STORAGE_CONNECTION = "DefaultEndpointsProtocol=https;AccountName=teststorage;AccountKey=EXAMPLEKEY1234567890abcdefghijklmnopqrstuvwxyz==;EndpointSuffix=core.windows.net"

@app.route('/api/azure/blobs', methods=['GET'])
def azure_blobs():
    return jsonify({'tenant': AZURE_TENANT_ID, 'client': AZURE_CLIENT_ID})

# ============================================================================
# Stripe Keys
# ============================================================================
STRIPE_SECRET_KEY = "sk_live_51EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz"
STRIPE_PUBLISHABLE_KEY = "pk_live_51EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz"
STRIPE_WEBHOOK_SECRET = "whsec_EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz"

@app.route('/api/payment/charge', methods=['POST'])
def charge_card():
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    return jsonify({'key_prefix': STRIPE_SECRET_KEY[:7]})

# ============================================================================
# GitHub / GitLab Tokens
# ============================================================================
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde12345"
GITHUB_OAUTH = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde12345"
GITLAB_TOKEN = "glpat-ABCDEFGHIJKLMNOPQRST"
GITLAB_RUNNER_TOKEN = "GR1348941ABCDEFGHIJKLMNOPQRST"

@app.route('/api/repos', methods=['GET'])
def list_repos():
    resp = requests.get('https://api.github.com/user/repos',
        headers={'Authorization': f'token {GITHUB_TOKEN}'})
    return jsonify({'status': resp.status_code})

# ============================================================================
# Database Connection Strings
# ============================================================================
POSTGRES_URL = "postgresql://admin:SuperSecret123!@prod-db.internal:5432/maindb"
MYSQL_URL = "mysql://root:R00tP@ssw0rd!@db-master.internal:3306/appdb"
MONGODB_URL = "mongodb://appuser:M0ng0P@ss!@mongo-cluster.internal:27017/production?authSource=admin"
REDIS_URL = "redis://:RedisSecret123@cache.internal:6379/0"

@app.route('/api/db/health', methods=['GET'])
def db_health():
    return jsonify({'postgres': POSTGRES_URL.split('@')[1], 'mongo': 'connected'})

# ============================================================================
# JWT / API / Generic Secrets
# ============================================================================
JWT_SECRET_KEY = "super-secret-jwt-signing-key-that-should-be-in-vault"
API_KEY_SENDGRID = "SG.EXAMPLE1234567890.abcdefghijklmnopqrstuvwxyz1234567890ABCD"
API_KEY_TWILIO = "SK1234567890abcdef1234567890abcdef"
TWILIO_AUTH_TOKEN = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPqrstuv"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

@app.route('/api/notify', methods=['POST'])
def send_notification():
    requests.post(SLACK_WEBHOOK, json={'text': request.json.get('message', '')})
    return jsonify({'sent': True})

# ============================================================================
# SSH / RSA Private Keys
# ============================================================================
SSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBEXAMPLEKEYDATATHATMATCHESFORMATBUTISNOTREALAAAAaEXAMPLE
PRIVATEDATAPADDINGTOMAKELENGTHLOOKREAL0123456789abcdefghijklmnopqrstuvwx
-----END OPENSSH PRIVATE KEY-----"""

RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoSo0ExAmPlEkEyDaTa1234
5678901234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv
wxyz0123456789/+ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst
EXAMPLEPADDINGTOMATCHRSAKEYLENGTH012345678901234567890ABCDEFGH==
-----END RSA PRIVATE KEY-----"""

@app.route('/api/deploy/key', methods=['GET'])
def get_deploy_key():
    return jsonify({'key_type': 'ed25519', 'fingerprint': 'SHA256:EXAMPLE'})

# ============================================================================
# CI/CD Tokens
# ============================================================================
CIRCLE_CI_TOKEN = "cc_EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz"
TRAVIS_TOKEN = "travis-EXAMPLE-token-1234567890abcdefghijklm"
JENKINS_API_TOKEN = "11a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
DOCKER_HUB_TOKEN = "dckr_pat_EXAMPLE1234567890abcdefghijklmno"

@app.route('/api/ci/trigger', methods=['POST'])
def trigger_build():
    requests.post('https://circleci.com/api/v2/project/gh/org/repo/pipeline',
        headers={'Circle-Token': CIRCLE_CI_TOKEN},
        json={'branch': 'main'})
    return jsonify({'triggered': True})

# ============================================================================
# UNREACHABLE: Secrets in dead code
# ============================================================================
def _dead_aws():
    """Never called — dead AWS secret."""
    OLD_KEY = "AKIAIOSFODNN7OLDEXAMP"
    OLD_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYOLDKEYEXAMP"
    boto3.client('s3', aws_access_key_id=OLD_KEY, aws_secret_access_key=OLD_SECRET)

def _dead_stripe():
    """Never called — dead Stripe key."""
    REVOKED_KEY = "sk_live_REVOKED567890abcdefghijklmnopqrstuvwxyz01"
    return REVOKED_KEY

def _dead_github():
    """Never called — rotated GitHub token."""
    OLD_TOKEN = "ghp_ROTATED1234567890abcdefghijklm67890"
    requests.get('https://api.github.com/user', headers={'Authorization': f'token {OLD_TOKEN}'})

def _dead_ssh_key():
    """Never called — decommissioned SSH key."""
    DEAD_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEADEADKEYFORTESTINGPURPOSESONLY1234567890abcdefgh
ijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh
-----END RSA PRIVATE KEY-----"""
    return DEAD_KEY

def _dead_db_url():
    """Never called — old database string."""
    OLD_POSTGRES = "postgresql://old_admin:OldP@ss123@decommissioned-db:5432/legacy"
    return OLD_POSTGRES

if __name__ == '__main__':
    app.run(port=5010)
