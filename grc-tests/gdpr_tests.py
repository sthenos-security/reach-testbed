# Copyright © 2026 Sthenos Security. All rights reserved.
"""
GRC Standards Test Suite — GDPR
=================================
Tests for General Data Protection Regulation compliance.
All findings map to GDPR Articles.

GDPR Articles exercised:
  Art. 5  — Principles of processing (data minimisation, storage limitation)
  Art. 6  — Lawfulness of processing (consent)
  Art. 9  — Special categories of data
  Art. 17 — Right to erasure
  Art. 25 — Data protection by design
  Art. 32 — Security of processing (encryption)
  Art. 33 — Breach notification
  Art. 35 — DPIA
"""

import hashlib
import logging
import json

gdpr_log = logging.getLogger("gdpr")

# =============================================================================
# GDPR Art. 5(1)(c) — Data minimisation violations
# Only collect data necessary for the purpose
# =============================================================================

def register_user_overly_broad(
    email: str,
    password: str,
    ssn: str,                   # VIOLATION: SSN not needed for account registration
    dob: str,                   # VIOLATION: DOB excessive for basic registration
    passport_number: str,       # VIOLATION: passport not needed
    mothers_maiden_name: str,   # VIOLATION: excessive data collection
    home_address: str,          # VIOLATION: address not needed for online account
    credit_card: str,           # VIOLATION: card collected at registration, not purchase
) -> dict:
    """User registration — collects far more PII than necessary."""
    return {
        "email": email,
        "ssn": ssn,
        "passport": passport_number,
        "credit_card": credit_card,
        "address": home_address,
    }


# =============================================================================
# GDPR Art. 9 — Special categories (biometric, health, political, religion)
# =============================================================================

class SpecialCategoryProcessor:
    """Processes GDPR Art. 9 special category data without explicit consent."""

    def store_health_data(self, user_id: int, diagnosis: str, medications: list) -> None:
        # VIOLATION: Art. 9 — health data stored without explicit consent mechanism
        record = {
            "user_id": user_id,
            "diagnosis": diagnosis,         # special category: health
            "medications": medications,
            "stored_at": "2026-02-22",
        }
        gdpr_log.info(f"Health data stored: {record}")  # also: PHI in log

    def store_biometric(self, user_id: int, fingerprint_hash: str, face_encoding: list) -> None:
        # VIOLATION: Art. 9 — biometric data stored without explicit consent
        biometric = {
            "user_id": user_id,
            "fingerprint": fingerprint_hash,
            "face_vector": face_encoding,   # biometric special category
        }
        # VIOLATION: biometric data in plain log
        gdpr_log.info(f"Biometric stored: user={user_id} fp={fingerprint_hash}")

    def profile_by_political_opinion(self, user_id: int, political_data: dict) -> None:
        # VIOLATION: Art. 9 — political opinion profiling without explicit consent
        profile = {"user_id": user_id, "political": political_data}
        # store to DB (simulated)
        pass

    HARDCODED_SPECIAL_DATA = {
        "user_id": 44221,
        "name": "Klaus Mueller",
        "religion": "Islam",              # Art. 9 special category
        "political_affiliation": "Green Party",  # Art. 9 special category
        "trade_union": "ver.di",          # Art. 9 special category
        "health_condition": "Epilepsy",   # Art. 9 special category
        "sexual_orientation": "bisexual", # Art. 9 special category
        "ssn_de": "12 345678 A 012",
        "iban": "DE89370400440532013000",
    }


# =============================================================================
# GDPR Art. 17 — Right to Erasure: no deletion capability
# =============================================================================

# VIOLATION: No erasure pathway — data stored permanently with no delete method
PERMANENT_USER_STORE: list = []

def add_user_no_erasure(name: str, email: str, ssn: str) -> None:
    # VIOLATION: PII added to permanent store with no erasure capability — Art. 17
    PERMANENT_USER_STORE.append({
        "name": name,
        "email": email,
        "ssn": ssn,
        "added": "2026-02-22",
        # no 'deleted_at', no TTL, no erasure flag
    })


# =============================================================================
# GDPR Art. 25 — Data protection by design
# =============================================================================

def create_analytics_event(user_email: str, action: str, ip: str) -> dict:
    # VIOLATION: Art. 25 — raw PII in analytics events (should be pseudonymised)
    return {
        "event": action,
        "user_email": user_email,   # should be hashed/pseudonymised
        "ip_address": ip,           # should be truncated per GDPR guidance
        "timestamp": "2026-02-22T09:00:00Z",
    }

def export_analytics_report() -> list:
    # VIOLATION: Analytics report includes raw personal data — Art. 25
    return [
        {"user_email": "alice.martin@gmail.com", "page_views": 142, "ip": "203.0.113.10"},
        {"user_email": "pierre.dubois@yahoo.fr",  "page_views": 87,  "ip": "198.51.100.5"},
        {"user_email": "hans.schmidt@web.de",     "page_views": 231, "ip": "192.0.2.22"},
    ]


# =============================================================================
# GDPR Art. 32 — Security of processing (weak crypto on personal data)
# =============================================================================

def encrypt_personal_data_weak(pii_dict: dict) -> str:
    # VIOLATION: Art. 32 — MD5 is not appropriate for GDPR encryption
    return hashlib.md5(json.dumps(pii_dict).encode()).hexdigest()

def store_password_insecure(email: str, password: str) -> dict:
    # VIOLATION: Art. 32 — password hashed with SHA1 (not bcrypt/argon2)
    import hashlib
    pw_hash = hashlib.sha1(password.encode()).hexdigest()
    return {"email": email, "password_hash": pw_hash}


# =============================================================================
# GDPR Art. 33 — Breach notification: personal data in exception messages
# =============================================================================

def process_gdpr_subject(name: str, email: str, ssn: str) -> None:
    # VIOLATION: Art. 33 — PII in exception (will appear in error reports/Sentry)
    if not email:
        raise ValueError(
            f"Invalid data subject: name='{name}' email=NULL ssn='{ssn}'"
        )
    gdpr_log.info(f"Processing data subject: {name} <{email}> ssn={ssn}")


# =============================================================================
# GDPR Art. 6 — Consent: collecting without consent mechanism
# =============================================================================

# Marketing email list built without consent tracking — VIOLATION Art. 6
MARKETING_LIST = [
    {"name": "Sophie Blanc",   "email": "sophie.blanc@gmail.com",  "consented": False},
    {"name": "Marco Rossi",    "email": "marco.rossi@libero.it",   "consented": False},
    {"name": "Ingrid Larsen",  "email": "ingrid.larsen@hotmail.no","consented": None},  # None = unknown
]

def send_marketing_without_consent(recipient_list: list) -> None:
    # VIOLATION: Art. 6 — sending marketing emails without verified consent
    for r in recipient_list:
        if not r.get("consented"):
            # sends anyway — GDPR violation
            print(f"Sending to {r['email']}")


# =============================================================================
# Cross-border transfer (GDPR Ch. V) — no adequacy decision
# =============================================================================

def transfer_eu_pii_to_us(user_records: list, us_endpoint: str) -> None:
    # VIOLATION: GDPR Ch. V — transferring EU personal data to US without SCCs/adequacy
    import urllib.request
    data = json.dumps(user_records).encode()
    req = urllib.request.Request(
        f"http://{us_endpoint}/import",  # also HTTP violation
        data=data, method="POST",
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)

    # EU PII being transferred
    EU_PII_RECORDS = [
        {"name": "François Lefevre", "email": "f.lefevre@orange.fr",  "ssn_fr": "1 85 12 75 108 001 77"},
        {"name": "Müller Bauer",     "email": "m.bauer@gmx.de",       "ssn_de": "12 345678 A 012"},
        {"name": "Emma Johnson",     "email": "e.johnson@btinternet.com", "nin_uk": "AB 12 34 56 C"},
    ]
