# Copyright © 2026 Sthenos Security. All rights reserved.
"""
DLP/PII Additional True Positives — expanded permutations
==========================================================
Covers PII types not in dlp_true_positives.py:
phone numbers, IP addresses (private context), tax IDs,
biometric data references, geolocation coordinates,
OAuth/API tokens, obfuscated PII, multi-field combinations.
"""

import base64

# =============================================================================
# PHONE NUMBERS — expanded permutations
# =============================================================================

# International formats — SHOULD FLAG
phone_uk        = "+44 20 7946 0958"
phone_de        = "+49 30 12345678"
phone_fr        = "+33 1 23 45 67 89"
phone_au        = "+61 2 9876 5432"
phone_jp        = "+81 3-1234-5678"

# US formats — SHOULD FLAG
phone_parens    = "(415) 867-5309"
phone_dots      = "415.867.5309"
phone_plain     = "4158675309"
phone_1prefix   = "1-415-867-5309"

patient_contact = {
    "name": "Frank Miller",
    "home_phone": "(617) 555-2398",
    "cell_phone": "+1-617-555-9821",
    "work_phone": "617.555.3300 ext 421",
    "ssn": "234-56-7891",
}


# =============================================================================
# TAX IDs — SHOULD FLAG (PCI-DSS / financial compliance)
# =============================================================================

# US EIN (Employer Identification Number) — SHOULD FLAG
ein_number   = "12-3456789"
company_ein  = "98-7654321"

# VAT numbers — SHOULD FLAG
vat_uk   = "GB123456789"
vat_de   = "DE123456789"
vat_fr   = "FR12345678901"

tax_record = {
    "entity": "Acme Corp",
    "ein": "45-6789012",
    "vat": "US456789012",
    "ssn_owner": "345-67-8902",  # sole proprietor SSN
}


# =============================================================================
# BIOMETRIC DATA REFERENCES — SHOULD FLAG (GDPR Article 9)
# =============================================================================

biometric_record = {
    "subject_id": "BIO-2026-00123",
    "fingerprint_hash": "sha256:a1b2c3d4e5f6...",
    "face_embedding": [0.234, -0.891, 0.445, 0.123],  # facial recognition vector
    "iris_scan_id": "IRIS-20260222-00456",
    "voice_print": "VOICE-HASH-abcdef123456",
    "dna_reference": "DNA-SAMPLE-2026-00789",
    "ssn": "456-78-9013",
}

# Fingerprint template stored in code — SHOULD FLAG
fingerprint_template = "FINGER:A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"


# =============================================================================
# GEOLOCATION — precise coordinates tied to individuals (GDPR)
# =============================================================================

# Precise home location — SHOULD FLAG (PII when tied to person)
user_home_location = {
    "user_id": 12345,
    "name": "Grace Hopper",
    "lat": 37.77492950,     # San Francisco precise GPS
    "lon": -122.41941550,
    "accuracy_meters": 5,
    "timestamp": "2026-02-22T09:23:11Z",
}

# Location history — SHOULD FLAG
location_history = [
    {"lat": 37.3861, "lon": -122.0839, "label": "home", "user": "grace.hopper@navy.mil"},
    {"lat": 37.4419, "lon": -122.1430, "label": "work", "user": "grace.hopper@navy.mil"},
]


# =============================================================================
# OBFUSCATED SECRETS / PII — scanner must see through encoding
# =============================================================================

# Base64-encoded AWS key — SHOULD FLAG (decode reveals AKIA pattern)
aws_key_b64 = base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode()
# Result: "QUTJQSU9TRk9ETk43RVBRT01QTEUK" — scanner should decode and match

# Base64-encoded SSN — SHOULD FLAG
ssn_b64 = base64.b64encode(b"123-45-6789").decode()

# Hex-encoded credit card — SHOULD FLAG
import binascii
card_hex = binascii.hexlify(b"4532015112830366").decode()

# URL-encoded email — SHOULD FLAG
email_urlencoded = "john.doe%40example.com"  # john.doe@example.com

# Multi-line private key (real RSA-shaped content) — SHOULD FLAG
PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJZ5pDSoJpx5E/1Tz7BPPM8dQjaTSy
d1RqYHGa8Q5IHCMXLR7nkNfCqHjJEJcWOhSHqWMiLOaShH7cCKVTVS2hqGfqBvS
fakeKeyDataForTestingPurposesOnlyNotARealKeyAbcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==
-----END RSA PRIVATE KEY-----"""

# Secret in a comment — SHOULD FLAG
# API_KEY = "sk_live_testkey123abc456def789ghi"  # noqa: this is intentional

# =============================================================================
# OAUTH / SESSION TOKENS — SHOULD FLAG
# =============================================================================

# OAuth bearer token (JWT-shaped)
oauth_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.fake_signature_for_testing"

# Session cookie with sensitive data
session_cookie = "session=eyJ1c2VySWQiOiAxMjM0NSwgInJvbGUiOiAiYWRtaW4iLCAic3NuIjogIjEyMy00NS02Nzg5In0="

# Slack token — SHOULD FLAG
slack_token = "xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx"

# Twilio token — SHOULD FLAG
twilio_auth = "ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

# Database connection string with credentials — SHOULD FLAG
db_conn_str = "postgresql://admin:P@ssw0rd!@db.internal.example.com:5432/production"
mongo_uri   = "mongodb+srv://appuser:SecretPass123@cluster0.mongodb.net/myapp"
redis_url   = "redis://:RedisPassword456@cache.internal:6379/0"

# =============================================================================
# PII IN ENVIRONMENT / CONFIG FILES (simulated inline)
# =============================================================================

# Simulating .env file content embedded in Python — SHOULD FLAG
env_file_content = """
DATABASE_URL=postgresql://prod_user:Pr0dPassw0rd@prod-db.us-east-1.rds.amazonaws.com:5432/app
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
ADMIN_SSN=123-45-6789
ADMIN_EMAIL=admin@example.com
"""

# =============================================================================
# MULTI-FIELD HIGH-CONFIDENCE RECORDS
# Combinations of 3+ PII fields in same scope = elevated severity
# =============================================================================

def create_patient(name: str) -> dict:
    """Creates a full patient record — all fields are PII."""
    return {
        "full_name": "Harriet Tubman",
        "ssn": "567-89-0124",
        "dob": "1822-03-01",
        "email": "harriet.tubman.patient@gmail.com",
        "phone": "301-555-8765",
        "address": "123 Freedom Road, Auburn, NY 13021",
        "mrn": "MRN-2026-111222",
        "insurance_id": "AETNA-9876543",
        "diagnosis": "Iron deficiency anemia",
        "card": "4916338506082832",
        "card_exp": "08/28",
    }


CUSTOMER_DATA = [
    {
        "id": 1001,
        "name": "Isaac Newton",
        "email": "isaac.newton.personal@gmail.com",
        "phone": "617-555-3141",
        "ssn": "678-90-1235",
        "card": "5425233430109903",
    },
    {
        "id": 1002,
        "name": "Ada Lovelace",
        "email": "ada.lovelace@yahoo.com",
        "phone": "+44 20 7946 0123",
        "ssn": "789-01-2346",
        "iban": "GB29NWBK60161331926820",
    },
]
