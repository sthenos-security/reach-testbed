"""
DLP/PII Edge Cases — Extended True Positives
=============================================
Additional PII types and obfuscation patterns that SHOULD be detected.
Covers: IP addresses as PII, geolocation, biometric references,
API keys (expanded), connection strings, OAuth tokens, session IDs,
obfuscated/encoded secrets, multi-line secrets.
"""

import base64

# =============================================================================
# API KEYS — expanded beyond generic/Stripe
# =============================================================================

# AWS (SHOULD FLAG)
aws_access_key_id     = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
aws_session_token     = "AQoXnyc4lcK4ZIkIALtOjLkRDsMkXWFTlGFEXAMPLE"

# Azure (SHOULD FLAG)
azure_subscription_id   = "12345678-1234-1234-1234-123456789012"
azure_tenant_id         = "87654321-4321-4321-4321-210987654321"
azure_client_secret     = "Az8Q~FakeAzureClientSecretForTestingOnly1234"
azure_storage_key       = "DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789=="

# GCP (SHOULD FLAG)
gcp_api_key             = "AIzaSyFakeGoogleAPIKeyForTestingPurposesOnly"
gcp_service_account_key = '{"type":"service_account","project_id":"my-project","private_key_id":"abc123","private_key":"-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQ...\\n-----END RSA PRIVATE KEY-----","client_email":"sa@my-project.iam.gserviceaccount.com"}'

# GitHub (SHOULD FLAG)
github_pat              = "ghp_16C7e42F292c6912E7710c838347Ae298G5Le"
github_app_secret       = "github_pat_11ABCDEFG0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Slack (SHOULD FLAG)
slack_bot_token         = "xoxb-1234567890-1234567890123-FakeSlackBotTokenForTesting"
slack_webhook           = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Twilio (SHOULD FLAG)
twilio_account_sid      = "ACfake1234567890abcdef1234567890ab"
twilio_auth_token       = "fake1234567890abcdef1234567890ab"

# SendGrid (SHOULD FLAG)
sendgrid_api_key        = "SG.FakeSendGridAPIKeyForTestingPurposesOnly.abcdefghijklmnopqrstuvwxyz"

# Stripe (SHOULD FLAG)
stripe_secret_key       = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
stripe_restricted_key   = "rk_live_FakeStripeRestrictedKeyForTesting1234567890"

# Anthropic (SHOULD FLAG)
anthropic_api_key       = "sk-ant-api03-FakeAnthropicAPIKeyForTestingPurposesOnlyABCDEFGHIJKLMNOP-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX-XXXXXXXXXX"

# OpenAI (SHOULD FLAG)
openai_api_key          = "sk-FakeOpenAIAPIKeyForTestingPurposesOnlyABCDEFGHIJKLMNOP"

# HuggingFace (SHOULD FLAG)
hf_token                = "hf_FakeHuggingFaceTokenForTestingPurposesABCDEFGHIJ"


# =============================================================================
# DATABASE CONNECTION STRINGS — expanded (SHOULD FLAG)
# =============================================================================

# PostgreSQL with credentials
pg_url          = "postgresql://admin:SuperSecret123@db.internal.example.com:5432/production"
pg_url_params   = "host=db.example.com port=5432 dbname=prod user=admin password=SuperSecret123"

# MySQL
mysql_url       = "mysql://root:RootPassword456@mysql.example.com:3306/app_db"

# MongoDB
mongo_url       = "mongodb+srv://admin:MongoSecret789@cluster0.abcde.mongodb.net/production"

# Redis with password
redis_url       = "redis://:RedisAuth012@redis.example.com:6379/0"

# Elasticsearch
es_url          = "https://elastic:ElasticSecret345@search.example.com:9200"

# Oracle
oracle_dsn      = "oracle://scott:tiger@oracledb.example.com:1521/ORCL"

# MSSQL
mssql_conn      = "Server=sql.example.com;Database=prod;User Id=sa;Password=MssqlPass678;"

# Connection strings in config dict (SHOULD FLAG)
DATABASE_CONFIG = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "production_db",
        "USER": "db_admin",
        "PASSWORD": "ProductionDbPass!2026",
        "HOST": "rds.example.com",
        "PORT": "5432",
    }
}


# =============================================================================
# OAUTH TOKENS / JWT — expanded (SHOULD FLAG)
# =============================================================================

# JWT with real-looking payload (SHOULD FLAG)
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# OAuth2 bearer token
oauth_bearer    = "Bearer ya29.FakeGoogleOAuthTokenForTestingPurposesOnly1234567890ABCDEF"
oauth_refresh   = "1//FakeRefreshTokenForTestingPurposesOnlyABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Session IDs — high entropy session tokens (SHOULD FLAG)
session_id      = "sess_abc123def456ghi789jkl012mno345pqr678stu901"
session_cookie  = "sessionid=abcdef1234567890abcdef1234567890; Path=/; HttpOnly; Secure"
flask_session   = "eyJ1c2VyX2lkIjoiMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0"


# =============================================================================
# OBFUSCATED / ENCODED SECRETS (SHOULD FLAG — decoder-aware detection)
# =============================================================================

# Base64-encoded secrets (SHOULD FLAG)
b64_aws_key     = base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode()
b64_password    = base64.b64encode(b"SuperSecretPassword123!").decode()
b64_connection  = base64.b64encode(b"postgresql://admin:pass@db:5432/prod").decode()

# Hex-encoded secret
hex_api_key     = "736b5f6c6976655f346543333948714c796a574461726a7454317a6470376463"  # Stripe key in hex

# URL-encoded credentials
url_encoded_cred = "admin%3ASuperSecret123%40db.example.com"  # admin:SuperSecret123@db


# =============================================================================
# MULTI-LINE SECRETS — PEM format (SHOULD FLAG)
# =============================================================================

RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29MNxBbTDfRwMi
FakeKeyDataForTestingPurposesOnlyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/====
-----END RSA PRIVATE KEY-----"""

EC_PRIVATE_KEY = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIFakeECPrivateKeyForTestingPurposesOnlyABCDEFGHIJKLMNOPQRSTU
oAoGCCqGSM49AwEHoWQDYgAEFakePublicKeyDataForTestingPurposesOnly123456
-----END EC PRIVATE KEY-----"""

SSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...FakeSSHKeyForTestingPurposesOnly...AAAA
-----END OPENSSH PRIVATE KEY-----"""

# Certificate (not a secret but contains identity info — SHOULD FLAG)
SSL_CERT = """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcN...FakeCertForTestingPurposesOnly...EQMAQwIBBQ==
-----END CERTIFICATE-----"""


# =============================================================================
# SECRETS IN COMMENTS (SHOULD FLAG)
# =============================================================================

# TODO: remove before prod — api_key = "sk_live_realKeyGoesHere1234"
# FIXME: hardcoded token below — Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.real
# Debug key: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

def connect_to_service():
    # Old credentials (still work): admin / OldPassword123!@db.example.com:5432
    pass


# =============================================================================
# SECRETS IN ENVIRONMENT FILES (.env patterns)
# =============================================================================

# These simulate what would be in a .env file loaded into Python
env_file_contents = """
DATABASE_URL=postgresql://admin:ProdPassword!99@rds.example.com:5432/production
STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SENDGRID_API_KEY=SG.FakeSendGridKey.ForTestingPurposesOnly1234567890abcdef
JWT_SECRET=super-secret-jwt-signing-key-minimum-32-characters-long!
REDIS_URL=redis://:RedisPassword123@redis.example.com:6379
"""


# =============================================================================
# GEOLOCATION DATA — PII in GDPR context (SHOULD FLAG)
# =============================================================================

user_location = {
    "user_id": "usr_12345",
    "name": "Alice Johnson",
    "latitude":  37.7749,       # San Francisco lat/lng — precise geolocation = PII
    "longitude": -122.4194,
    "accuracy_meters": 10,
    "timestamp": "2026-02-22T14:30:00Z",
}

gps_track = [
    {"lat": 37.7749, "lng": -122.4194, "time": "2026-02-22T09:00:00Z"},
    {"lat": 37.7751, "lng": -122.4190, "time": "2026-02-22T09:05:00Z"},
    {"lat": 37.7755, "lng": -122.4185, "time": "2026-02-22T09:10:00Z"},
]


# =============================================================================
# BIOMETRIC DATA REFERENCES (SHOULD FLAG — GDPR/CCPA sensitive category)
# =============================================================================

biometric_record = {
    "user_id": "usr_67890",
    "name": "Bob Smith",
    "fingerprint_hash": "sha256:abc123def456...",
    "face_embedding": [0.123, 0.456, 0.789, 0.012],  # Face recognition vector
    "voice_print": "voiceprint_data_base64_encoded==",
    "retinal_scan_id": "ret_scan_2026_001234",
}


# =============================================================================
# TAX IDs — EIN, VAT, ITIN (SHOULD FLAG)
# =============================================================================

ein_number      = "12-3456789"      # US Employer Identification Number
itin_number     = "900-70-1234"     # US Individual Taxpayer ID
vat_uk          = "GB 123 4567 89"  # UK VAT number
vat_eu          = "DE123456789"     # German VAT
vat_fr          = "FR12345678901"   # French VAT

company_tax_info = {
    "company": "Sthenos Security",
    "ein": "45-6789012",
    "state_tax_id": "CA-SB-2026-98765",
    "vat_number": "US-12-3456789",
}


# =============================================================================
# COMBINED: API Key + PII in one record (maximum severity)
# =============================================================================

DEPLOYMENT_SECRETS = {
    # Infrastructure secrets
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "db_password":    "ProductionDbP@ss!2026",
    "jwt_secret":     "super-secret-jwt-key-32-chars-minimum!!",
    # Admin PII
    "admin_email":    "cto@sthenosecurity.com",
    "admin_phone":    "415-555-0100",
    "admin_ssn":      "123-45-6789",
    "admin_dob":      "1980-01-15",
}
