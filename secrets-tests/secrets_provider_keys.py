# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Triggers: Semgrep secrets rules across all major provider patterns
# Tests both REACHABLE (used in routes) and UNREACHABLE (dead code) secrets
# ============================================================================
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# ============================================================================
# AWS SECRETS (REACHABLE — used in routes below)
# ============================================================================
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_SESSION_TOKEN = "FwoGZXIvYXdzEBYaDHqa0AP1z0Gf3arT6CLIAd3r+example+token+here+padding"

# GCP SERVICE ACCOUNT KEY (REACHABLE)
GCP_SERVICE_ACCOUNT_KEY = '{"type":"service_account","project_id":"test-proj","private_key_id":"key123","private_key":"-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY\\n-----END RSA PRIVATE KEY-----\\n","client_email":"test@test-proj.iam.gserviceaccount.com"}'

# AZURE (REACHABLE)
AZURE_CLIENT_SECRET = "abc8Q~defghijklmnopqrstuvwxyz123456"
AZURE_STORAGE_KEY = "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF01234567==;EndpointSuffix=core.windows.net"

# STRIPE KEYS (REACHABLE)
STRIPE_SECRET_KEY = "sk_live_51HG3bCKr4F8Rp0YMabcdefghijklmnopqrstuvwxyz"
STRIPE_PUBLISHABLE_KEY = "pk_live_51HG3bCKr4F8Rp0YMabcdefghijklmnop"

# GITHUB TOKENS (REACHABLE)
GITHUB_PAT = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01"
GITHUB_OAUTH_SECRET = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"

# SLACK (REACHABLE)
SLACK_BOT_TOKEN = "xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPqrstuv"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T01ABCDEF/B01GHIJKL/abcdefghijklmnopqrstuvwx"

# TWILIO (REACHABLE)
TWILIO_AUTH_TOKEN = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
TWILIO_ACCOUNT_SID = "ACabcdef0123456789abcdef0123456789"

# SENDGRID (REACHABLE)
SENDGRID_API_KEY = "SG.abcdefghijklmnop.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-ab"

# DATABASE CONNECTION STRINGS (REACHABLE)
POSTGRES_URL = "postgresql://admin:SuperSecret123!@db.example.com:5432/production"
MYSQL_URL = "mysql://root:P@ssw0rd!@mysql.example.com:3306/app_db"
MONGODB_URL = "mongodb://admin:M0ng0P@ss@cluster0.example.mongodb.net:27017/prod?authSource=admin"
REDIS_URL = "redis://default:RedisSecret!@redis.example.com:6379/0"

# JWT / GENERIC SECRETS (REACHABLE)
JWT_SECRET = "my-super-secret-jwt-key-that-should-not-be-here-ever"
ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"
API_MASTER_KEY = "mk_live_abcdef0123456789abcdef0123456789"

# SSH PRIVATE KEY (REACHABLE)
SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY1FJPPuGT8VEBi2ALWOMR
YHhGKEsTiJkxqlSBjpqC4LCfnS7BPxVIBx8IPkPhVHnG0WMCf0WL3jJCb+fOMnW7
k6bBSaFDg7LHma+rHGzK2FQTiKBrgQFanMRPMxJp8LNByEa5M3s6jkVN4w0dv5d8
-----END RSA PRIVATE KEY-----"""

# ============================================================================
# REACHABLE ROUTES — Secrets used in live code paths
# ============================================================================
@app.route('/api/aws/s3/list', methods=['GET'])
def list_s3_buckets():
    import boto3
    client = boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        aws_session_token=AWS_SESSION_TOKEN)
    return jsonify({'buckets': str(client.list_buckets())})

@app.route('/api/stripe/charge', methods=['POST'])
def create_charge():
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    charge = stripe.Charge.create(amount=1000, currency='usd', source=request.json.get('token'))
    return jsonify({'charge_id': charge.id})

@app.route('/api/github/repos', methods=['GET'])
def list_repos():
    resp = requests.get('https://api.github.com/user/repos',
        headers={'Authorization': f'token {GITHUB_PAT}'})
    return jsonify(resp.json())

@app.route('/api/slack/send', methods=['POST'])
def send_slack():
    msg = request.json.get('message', '')
    requests.post(SLACK_WEBHOOK_URL, json={'text': msg})
    return jsonify({'status': 'sent'})

@app.route('/api/db/query', methods=['POST'])
def db_query():
    import psycopg2
    conn = psycopg2.connect(POSTGRES_URL)
    cur = conn.cursor()
    cur.execute(request.json.get('sql', 'SELECT 1'))
    return jsonify({'rows': cur.fetchall()})

@app.route('/api/notify/sms', methods=['POST'])
def send_sms():
    from twilio.rest import Client
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    msg = client.messages.create(
        body=request.json.get('body', ''), to=request.json.get('to', ''), from_='+15551234567')
    return jsonify({'sid': msg.sid})

@app.route('/api/email/send', methods=['POST'])
def send_email():
    import sendgrid
    sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
    return jsonify({'status': 'sent'})

@app.route('/api/auth/verify', methods=['POST'])
def verify_jwt():
    import jwt
    token = request.json.get('token', '')
    payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    return jsonify({'payload': payload})

@app.route('/api/ssh/connect', methods=['POST'])
def ssh_connect():
    import paramiko
    key = paramiko.RSAKey.from_private_key_string(SSH_PRIVATE_KEY)
    return jsonify({'fingerprint': key.get_fingerprint().hex()})

# ============================================================================
# UNREACHABLE — Secrets in dead code (should be filtered by reachability)
# ============================================================================
DEAD_DATADOG_API_KEY = "ddabcdef0123456789abcdef01234567"
DEAD_NEWRELIC_KEY = "NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DEAD_MAILGUN_KEY = "key-abcdef0123456789abcdef01234567"
DEAD_OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"

def _dead_datadog():
    requests.post('https://api.datadoghq.com/api/v1/series',
        headers={'DD-API-KEY': DEAD_DATADOG_API_KEY}, json={})

def _dead_openai():
    import openai
    openai.api_key = DEAD_OPENAI_KEY
    openai.ChatCompletion.create(model='gpt-4', messages=[])

def _dead_mailgun():
    requests.post('https://api.mailgun.net/v3/example.com/messages',
        auth=('api', DEAD_MAILGUN_KEY), data={})

if __name__ == '__main__':
    app.run(port=5010)
