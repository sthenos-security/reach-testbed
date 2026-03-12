# Copyright © 2026 Sthenos Security. All rights reserved.
"""
DLP/PII EXTENDED TRUE POSITIVES — Python
==========================================
Covers PII types beyond the original 5 (name, email, card, address, SSN).
All items here SHOULD generate DLP findings.

New categories:
  - Phone numbers (US + international)
  - IP addresses used as personal identifiers
  - Passport / driver's license / national ID
  - Bank account / routing / IBAN
  - Medical record numbers / DEA numbers / insurance IDs
  - Tax IDs (EIN, VAT, ITIN)
  - Biometric references
  - OAuth / session tokens (credential-class PII)
  - Geolocation coordinates tied to individuals
  - Combined high-risk records
"""

# =============================================================================
# PHONE NUMBERS — Extended (TRUE POSITIVE)
# =============================================================================

# US formats
us_phone_dashes    = "415-555-9876"
us_phone_dots      = "415.555.9876"
us_phone_parens    = "(415) 555-9876"
us_phone_intl      = "+1-415-555-9876"
us_phone_e164      = "+14155559876"
us_phone_tollfree  = "1-800-555-0199"   # real toll-free range, not 555 test

# International formats — SHOULD FLAG (personal numbers)
uk_mobile          = "+44 7911 123456"
german_mobile      = "+49 170 1234567"
french_mobile      = "+33 6 12 34 56 78"
indian_mobile      = "+91 98765 43210"
australian_mobile  = "+61 412 345 678"
canadian_mobile    = "+1 416 555 0198"

# Phone in a customer record — SHOULD FLAG
customer_record = {
    "id": 9001,
    "name": "Frances Kim",
    "phone": "+1-650-555-0234",
    "backup_phone": "650.555.9821",
    "ssn": "321-54-9876",
}


# =============================================================================
# IP ADDRESSES AS PERSONAL IDENTIFIERS — TRUE POSITIVE
# (GDPR considers IP addresses personal data when linked to a person)
# =============================================================================

# Stored IP addresses linked to user sessions — SHOULD FLAG
user_session = {
    "user_id": 42,
    "ip_address": "203.0.113.45",      # RFC 5737 documentation range, but still IP PII
    "login_ip": "198.51.100.22",
    "last_seen_ip": "192.0.2.178",
}

audit_entry = {
    "action": "password_change",
    "user_email": "frank.castle@example.com",
    "source_ip": "203.0.113.99",
    "timestamp": "2026-02-22T09:15:00Z",
}

# IPv6 as PII
user_ipv6 = "2001:db8:85a3::8a2e:370:7334"   # linked to a specific user session


# =============================================================================
# PASSPORT / DRIVER'S LICENSE / NATIONAL ID — TRUE POSITIVE
# =============================================================================

# US passport
us_passport_num    = "123456789"       # 9-digit US passport number
us_passport_alt    = "A12345678"       # Alpha-prefix format

# UK passport
uk_passport        = "536452678"       # 9-digit UK passport

# Driver's licenses (US state formats)
ca_drivers_license = "D1234567"        # California DL format (D + 7 digits)
ny_drivers_license = "123 456 789"     # New York DL format
tx_drivers_license = "12345678"        # Texas DL (8 digits)
fl_drivers_license = "A123-456-78-910-0"  # Florida DL

# National IDs
uk_nin             = "AB 12 34 56 C"   # UK National Insurance Number
canadian_sin       = "123 456 789"     # Canadian Social Insurance Number
german_id          = "L01X00T471"      # German national ID card format

kyc_document = {
    "customer_id": "CUST-2026-8891",
    "id_type": "passport",
    "id_number": "B98765432",
    "id_country": "US",
    "issue_date": "2020-01-15",
    "expiry_date": "2030-01-14",
}


# =============================================================================
# BANK ACCOUNT / ROUTING / IBAN / SWIFT — TRUE POSITIVE
# =============================================================================

# US bank account numbers
checking_account   = "123456789012"
savings_account    = "987654321098"
routing_number_aba = "021000021"       # real JPMorgan Chase routing

# IBAN (International Bank Account Number)
iban_gb            = "GB29NWBK60161331926819"
iban_de            = "DE89370400440532013000"
iban_fr            = "FR7630006000011234567890189"

# SWIFT/BIC codes
swift_code         = "CHASUS33"       # JPMorgan Chase US
swift_full         = "BNPAFRPPXXX"   # BNP Paribas Paris

# Wire transfer record — SHOULD FLAG (multiple financial PII)
wire_record = {
    "sender_name": "Grace Hopper",
    "sender_account": "456789012345",
    "sender_routing": "021000021",
    "sender_iban": "GB29NWBK60161331926819",
    "receiver_name": "Ada Lovelace",
    "receiver_account": "321098765432",
    "amount_usd": 25000.00,
}


# =============================================================================
# TAX IDENTIFIERS — TRUE POSITIVE
# =============================================================================

# US EIN (Employer Identification Number)
company_ein        = "12-3456789"
ein_nodash         = "123456789"

# US ITIN (Individual Taxpayer Identification Number)
itin               = "900-70-0000"    # ITINs start with 9, 7x range

# VAT numbers (EU)
vat_uk             = "GB 123 4567 89"
vat_de             = "DE123456789"
vat_fr             = "FR 12 345678901"

tax_filing = {
    "taxpayer_name": "Henry Ford",
    "ein": "87-6543210",
    "itin": "900-88-1234",
    "tax_year": 2025,
    "ssn": "567-89-0123",
}


# =============================================================================
# MEDICAL RECORD / HEALTH INSURANCE / DEA — TRUE POSITIVE (HIPAA)
# =============================================================================

# Medical record numbers
mrn_format1        = "MRN-2026-001234"
mrn_format2        = "0012345678"      # 10-digit MRN

# Health insurance / payer IDs
insurance_id_bcbs  = "BCBS-1234567890"
insurance_id_uhc   = "UHC-9876543210"
medicare_id        = "1EG4-TE5-MK72"   # Medicare Beneficiary Identifier format
medicaid_id        = "CA-M-123456789"

# DEA numbers (controlled substance prescriptions)
dea_number         = "AB1234563"       # format: 2 letters + 7 digits + checksum
dea_number2        = "FH3456782"

phi_record = {
    "patient_name": "Iris West",
    "dob": "1990-11-30",
    "mrn": "MRN-2026-077421",
    "ssn": "234-56-7890",
    "diagnosis_code": "E11.9",        # ICD-10 for T2 diabetes
    "insurance_id": "BCBS-0099887766",
    "provider_npi": "1234567890",     # National Provider Identifier
}


# =============================================================================
# BIOMETRIC DATA REFERENCES — TRUE POSITIVE (GDPR Art. 9 special category)
# =============================================================================

# Fingerprint hash references
fingerprint_hash   = "FP_SHA256:a3f5c2d8e1b4f9c0a7d2e5b8f1c4a7d0"
iris_scan_ref      = "IRIS_ID:2026-02-15-USER-00441-LEFT"
face_embedding_id  = "FACE_VEC:user_9912_embedding_v3"
voice_print_id     = "VOICE:VPRINT_2026_441_SHA512"

biometric_record = {
    "user_id": 9912,
    "biometric_type": "fingerprint",
    "template_hash": "FP_SHA256:9a8f7e6d5c4b3a2190807060504030",
    "capture_device": "scanner_003",
    "enrolled_at": "2026-01-10T14:22:00Z",
}


# =============================================================================
# GEOLOCATION TIED TO INDIVIDUALS — TRUE POSITIVE (GDPR location data)
# =============================================================================

# GPS coordinates with user context — SHOULD FLAG
user_location = {
    "user_id": 5512,
    "latitude": 37.7749,
    "longitude": -122.4194,
    "accuracy_meters": 10,
    "timestamp": "2026-02-22T08:45:00Z",
}

home_gps = {
    "name": "Jack Ryan",
    "home_lat": 38.9072,
    "home_lng": -77.0369,
    "home_address": "1600 Pennsylvania Ave NW, Washington DC 20500",
}

tracking_log = [
    {"user_id": 1001, "lat": 40.7128, "lng": -74.0060, "ts": "2026-02-22T08:00:00Z"},
    {"user_id": 1001, "lat": 40.7580, "lng": -73.9855, "ts": "2026-02-22T08:30:00Z"},
    {"user_id": 1001, "lat": 40.7488, "lng": -73.9680, "ts": "2026-02-22T09:00:00Z"},
]


# =============================================================================
# SESSION / AUTH TOKENS TIED TO IDENTITY — TRUE POSITIVE
# =============================================================================

# OAuth access tokens (real formats — all fake values)
oauth_access_token  = "ya29.a0ARrdaM-FAKE_GOOGLE_OAUTH_ACCESS_TOKEN_xyzabc123"
oauth_refresh_token = "1//0gFAKE_REFRESH_TOKEN_google_xyzabc123defghi456"
github_oauth_token  = "gho_16C7e42F292c6912E7710c838347Ae298G5Le"

# Session IDs (high-entropy, tied to a user session)
session_id          = "sess_8Kj2mNpQ7vRx4Yz9wLdE3FtHs6CbAo1G"
flask_session       = "eyJsb2dnZWRfaW4iOnRydWV9.FakeFlaskSessionCookie.abc123"

# Cookies with PII
auth_cookie         = "auth=user_id=9912; ssn=123-45-6789; expires=Thu, 01-Jan-2026"
tracking_cookie     = "uid=EMAIL%3Ajohn.doe%40example.com; path=/"

session_store = {
    "session_id": "sess_Ax7Bz2Ky4Lm8Np1Qr5Ts9Vw3Xy6Za0Bc",
    "user_id": 8823,
    "email": "quinn.bergman@personalmail.com",
    "ip": "203.0.113.77",
    "created_at": "2026-02-22T07:00:00Z",
}


# =============================================================================
# OBFUSCATED / ENCODED PII — TRUE POSITIVE (should still be detected)
# =============================================================================

import base64

# Base64-encoded SSN — SHOULD FLAG (encoded PII is still PII)
ssn_b64 = base64.b64encode(b"123-45-6789").decode()    # MTIzLTQ1LTY3ODk=
card_b64 = base64.b64encode(b"4532015112830366").decode()

# Hex-encoded card number
card_hex = "4532015112830366".encode().hex()            # 34353332...

# URL-encoded email
email_urlenc = "john.doe%40gmail.com"

# PII in environment variable value (not reference)
import os
os.environ["BACKUP_SSN"] = "456-78-9012"    # storing PII in env var
os.environ["EMERGENCY_CARD"] = "4532015112830366"


# =============================================================================
# FULL HIGH-RISK COMBINED RECORDS (maximum finding density)
# =============================================================================

# Customer 360 record — all PII types present
CUSTOMER_360 = {
    # Identity
    "name": "Samantha Clarke",
    "dob": "1988-07-04",
    "ssn": "890-12-3456",
    "passport": "C78901234",
    "drivers_license": "D7890123",
    # Contact
    "email": "sam.clarke.personal@gmail.com",
    "phone": "+1-212-555-0177",
    "address": "42 Wallaby Way, Sydney NSW 2000, Australia",
    # Financial
    "credit_card": "5425233430109903",   # Luhn-valid Mastercard
    "card_cvv": "819",
    "card_expiry": "08/28",
    "bank_account": "789012345678",
    "routing_number": "021000021",
    "iban": "GB29NWBK60161331926819",
    # Health
    "mrn": "MRN-2026-112233",
    "insurance_id": "UHC-5544332211",
    "diagnosis": "Major Depressive Disorder",  # sensitive PHI
    # Location
    "home_lat": -33.8688,
    "home_lng": 151.2093,
    # Auth
    "session_token": "sess_Zq9Xm3Ky7Lp2Nr5Ts8Vw1Xy4Za6Bc0De",
    "oauth_token": "ya29.FAKE_TOKEN_samclarke_xyz",
}

# Employee HR record
HR_RECORD = {
    "employee_id": "EID-2026-009912",
    "name": "Marcus Webb",
    "ssn": "901-23-4567",
    "dob": "1975-12-01",
    "email": "marcus.webb.personal@yahoo.com",
    "phone": "773-555-0198",
    "home_address": "8801 South Michigan Ave, Chicago, IL 60619",
    "ein": "20-1234567",
    "bank_account": "654321098765",
    "routing": "071000013",
    "salary": 185000,
    "healthcare_id": "BCBS-3344556677",
}
