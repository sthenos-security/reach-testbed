# Copyright © 2026 Sthenos Security. All rights reserved.
"""
DLP/PII FALSE POSITIVE REGRESSION TESTS — Python
==================================================
These patterns MUST NOT trigger DLP alerts.
Every item here has caused false positives in prior releases.
Expected: ZERO findings from this file.

Rationale for each suppression annotated below.
"""

# =============================================================================
# WORD-BOUNDARY FALSE POSITIVES — substring match traps
# Regression: 'pan' in 'span', 'company', 'expand', 'Japan'
# Regression: 'name' in 'serviceName', 'filename', 'username'
# =============================================================================

# Should NOT flag — 'pan' is a substring of these common words
span_element = "<span class='highlight'>text</span>"
company_name = "Sthenos Security"  # correct company name
expand_options = ["--expand", "--no-expand"]
Japan_region = "Asia/Tokyo"
napkin_note = "Use a napkin"
expand_all = True
company_display = "Sthenos Security"
panorama_url = "https://panorama.example.com"
transparent_bg = True

# Should NOT flag — 'name' is a substring
service_name = "authentication-service"
filename_prefix = "report_2026"
username_field = "input[name='username']"
last_name_col = "lastName"
hostname = "api.internal.example.com"
column_names = ["firstName", "lastName", "serviceName", "codeName"]
rename_fn = lambda x: x.replace("old", "new")
nickname_field = "nickname"
domain_name = "example.com"

# Should NOT flag — 'card' substring
discard_list: list = []
scorecard_url = "https://scorecard.example.com/report"
cardboard_box = "cardboard packaging"
card_view_component = "CardView"  # React component name

# Should NOT flag — 'phone' substring
microphone_id = "mic_device_001"
saxophone_player = "jazz"
iphone_model = "iPhone 15 Pro"
earphone_type = "in-ear"

# Should NOT flag — 'ssn' substring
assignment_operator = "ssn't a keyword"
session_id = "ssn_session_abc123"  # variable name contains 'ssn' but not a SSN value


# =============================================================================
# TEMPLATE VARIABLES — should NOT flag
# Regression: ${{ secrets.GITHUB_TOKEN }}, ${VAR_NAME}, {{.Field}}
# =============================================================================

# GitHub Actions / CI patterns
ci_token_ref = "${{ secrets.GITHUB_TOKEN }}"
ci_token_ref2 = "${{ secrets.AWS_ACCESS_KEY_ID }}"
ci_step_output = "${{ steps.login.outputs.token }}"
ci_env_var = "${STRIPE_API_KEY}"
ci_bash_var = "$API_KEY"
helm_template = "{{ .Values.image.tag }}"
jinja_template = "{{ user.email }}"
django_template = "{% csrf_token %}"
go_template = "{{.AccessKey}}"
terraform_var = "${var.aws_access_key}"
shell_expansion = "$(echo $SECRET_KEY)"

# Environment variable references (not values) — should NOT flag
import os
db_url = os.environ.get("DATABASE_URL", "")
api_key = os.environ.get("API_KEY", "")
secret_key = os.getenv("SECRET_KEY")
jwt_secret = os.getenv("JWT_SECRET", "")


# =============================================================================
# CI/CD WORKFLOW PATTERNS — should NOT flag
# Regression: job names like 'secrets:', detect-secrets commands
# =============================================================================

# These are YAML strings representing CI/CD workflow content, not real secrets
ci_workflow_snippet = """
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - run: detect-secrets scan
      - run: echo "checking for secrets"
"""

detect_secrets_cmd = "detect-secrets scan --baseline .secrets.baseline"
secret_scan_step = "run: secret-scanner --repo ."
secrets_job_name = "secrets"  # job name, not a secret value


# =============================================================================
# TEST / FIXTURE DATA — should NOT flag (path-based suppression)
# NOTE: This file IS in dlp-tests/ which is a test path — suppressed at gate 1
# The patterns below validate that test-path suppression works correctly.
# =============================================================================

# These would be true positives if found in production code
# but this file is in a test directory — path gate should suppress
TEST_SSN = "111-22-3333"           # test fixture SSN
TEST_CARD = "4111111111111111"      # well-known Visa test card (Luhn-valid)
TEST_EMAIL = "test@example.com"    # generic test email
MOCK_PHONE = "555-555-5555"        # obviously fake test phone
SAMPLE_ADDRESS = "1 Test Street, Testville, TS 00000"


# =============================================================================
# MASKED / REDACTED DATA — should NOT flag (sanitizer detection)
# =============================================================================

# Masked credit card (sanitizer detected)
masked_card = "4532-****-****-0366"
masked_card2 = "XXXX-XXXX-XXXX-1234"
masked_pan = "************1117"
redacted_ssn = "XXX-XX-6789"
censored_ssn = "***-**-1234"
tokenized_card = "tok_visa_1234567890abcdef"  # Stripe token, not raw PAN

# Hash of PII (not PII itself)
import hashlib
hashed_email = hashlib.sha256(b"user@example.com").hexdigest()
hashed_ssn = hashlib.sha256(b"123-45-6789").hexdigest()

# Encrypted blob reference
encrypted_pii = "AES256:encryptedblob==base64data=="


# =============================================================================
# NUMERIC PATTERNS THAT LOOK LIKE CARDS BUT AREN'T — Luhn-check regression
# These fail Luhn check and should NOT be flagged as credit cards
# =============================================================================

# Luhn-invalid 16-digit numbers
not_a_card_1 = "1234567890123456"   # fails Luhn
not_a_card_2 = "9999999999999999"   # fails Luhn
not_a_card_3 = "0000000000000000"   # fails Luhn
version_number = "4532015112830000"  # close to real card but Luhn-invalid

# IDs that look like card numbers
order_id = "4532012345678901"   # Order ID — Luhn-invalid, just looks like Visa
invoice_id = "5425123456789000"  # Invoice ID — Luhn-invalid
product_sku = "4111000011110000"  # SKU — Luhn-invalid


# =============================================================================
# SSN-SHAPED VALUES THAT AREN'T SSNs — format regression
# =============================================================================

# ZIP+4 postal code — NOT an SSN
zip4 = "941-05-1234"           # looks like SSN format but is ZIP+4
zip4_alt = "94105-1234"

# Phone numbers in SSN-ish format — NOT an SSN
phone_as_ssn_shape = "415-55-1234"   # 3-2-4 digit pattern

# Date-shaped strings — NOT an SSN
date_yyyymmdd = "202-60-2022"   # date fragment, not SSN

# Employee/product IDs that match XXX-XX-XXXX but aren't SSNs
employee_id = "EMP-12-3456"    # has letters, not SSN
product_id = "SKU-00-0001"     # has letters, not SSN
ticket_id = "TKT-22-9847"      # has letters, not SSN


# =============================================================================
# EMAIL-SHAPED STRINGS THAT AREN'T PERSONAL PII
# =============================================================================

# System/service emails — acceptable in code
noreply_email = "noreply@example.com"
system_email = "system@internal.sthenosec.com"
support_email = "info@sthenosec.com"
alerts_email = "alerts@monitoring.internal"

# Placeholder/example emails used in documentation/tests
placeholder_email = "user@example.com"
example_email = "someone@yourdomain.com"
doc_email = "admin@yourcompany.com"
dummy_email = "foo@bar.com"

# Config keys that contain 'email' as a key name but no PII value
email_config = {"email_field": "email", "email_regex": r"[^@]+@[^@]+\.[^@]+"}
smtp_config = {"smtp_host": "smtp.sendgrid.net", "smtp_port": 587}


# =============================================================================
# PHONE-SHAPED VALUES THAT AREN'T REAL PHONE NUMBERS
# =============================================================================

# Toll-free / obviously fake / test numbers — NOT personal PII
info_line = "1-800-555-0100"        # 555 exchange = reserved for fiction/test
test_phone = "555-555-5555"         # obviously fake
docs_phone = "(555) 123-4567"       # 555 in area code = test
hotline = "1-888-555-1212"          # 555 exchange

# Port numbers that look like phone fragments
port_fragment = "443:8080"
config_pair = "3306:5432"


# =============================================================================
# ADDRESS-SHAPED STRINGS THAT AREN'T HOME ADDRESSES
# =============================================================================

# IP addresses — NOT physical addresses
ip_address = "192.168.1.100"
ipv6_address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
cidr_block = "10.0.0.0/16"

# File system paths — NOT physical addresses
file_path = "/var/app/data/reports"
windows_path = "C:\\Program Files\\App\\config"
url_path = "https://api.example.com/v1/users/123"

# Street-number-like config values
port_mapping = "127.0.0.1:8080"
version_string = "1.2.3 Build 456"


# =============================================================================
# KNOWN SAFE PATTERNS USED IN LOGGING / OBSERVABILITY
# =============================================================================

# Structured log fields with no PII values
import logging
logger = logging.getLogger(__name__)

def log_request(request_id: str, user_id: int, action: str) -> None:
    # Logging user_id (not email/SSN/PAN) is acceptable
    logger.info("request_id=%s user_id=%d action=%s", request_id, user_id, action)

def log_error(error_code: str, message: str) -> None:
    # No PII in error log
    logger.error("error_code=%s message=%s", error_code, message)


# =============================================================================
# DOCUMENTATION STRINGS / COMMENTS — should NOT flag
# These appear in docstrings describing PII fields, not storing actual PII
# =============================================================================

class UserModel:
    """
    User model with PII fields.
    Fields:
      - ssn: Social Security Number (encrypted at rest)
      - credit_card: Payment card number (tokenized via Stripe)
      - email: User email address
      - phone: Contact phone number
    All PII fields are encrypted. Never log raw values.
    """

    def __init__(self):
        # These are field descriptors, NOT actual PII values
        self.ssn: str = ""          # encrypted SSN field
        self.credit_card: str = ""  # Stripe token, not raw PAN
        self.email: str = ""        # user email
        self.phone: str = ""        # user phone
        self.name: str = ""         # display name

    def mask_ssn(self, ssn: str) -> str:
        """Return masked SSN: XXX-XX-1234"""
        return f"XXX-XX-{ssn[-4:]}"

    def mask_card(self, pan: str) -> str:
        """Return masked PAN: ****-****-****-1234"""
        return f"****-****-****-{pan[-4:]}"


# =============================================================================
# REGEX PATTERNS FOR PII DETECTION — code that detects PII, not contains it
# =============================================================================

import re

# These are regex patterns used to DETECT PII — should NOT themselves trigger
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
CREDIT_CARD_PATTERN = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_PATTERN = re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')

PII_PATTERNS = {
    "ssn": SSN_PATTERN,
    "credit_card": CREDIT_CARD_PATTERN,
    "email": EMAIL_PATTERN,
    "phone": PHONE_PATTERN,
}

def scan_for_pii(text: str) -> dict:
    """Scan text for PII patterns. Returns matches by type."""
    results = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            results[pii_type] = len(matches)
    return results
