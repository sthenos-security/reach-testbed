# Copyright © 2026 Sthenos Security. All rights reserved.
"""
GRC Standards Test Suite — NIST 800-53 / FedRAMP / CMMC 2.0
=============================================================
Tests aligned to federal security frameworks.

Controls exercised:
  AC-2  — Account Management (shared/default credentials)
  AC-6  — Least Privilege (overly permissive IAM)
  AU-2  — Event Logging (PHI in logs)
  IA-5  — Authenticator Management (weak passwords, hardcoded keys)
  SC-8  — Transmission Confidentiality (cleartext)
  SC-13 — Cryptographic Protection (weak ciphers)
  SC-28 — Protection of Information at Rest (plaintext PII)
  SI-10 — Information Input Validation (injection vulnerabilities)
  CM-6  — Configuration Settings (insecure defaults)
  CA-7  — Continuous Monitoring (no audit trail)

CMMC 2.0 Level 2 Practices (aligns with NIST 800-171):
  3.1.1  — Limit system access
  3.3.1  — Create and retain audit logs
  3.5.3  — Use multifactor authentication
  3.13.8 — Implement cryptographic mechanisms for transmission
  3.13.10 — Protect CUI at rest with encryption
"""

import hashlib
import subprocess
import logging

nist_log = logging.getLogger("nist")

# =============================================================================
# AC-2 / CMMC 3.1.1 — Account Management: hardcoded/shared credentials
# =============================================================================

# VIOLATION: Hardcoded credentials — IA-5(1), CMMC 3.5.3
SYSTEM_ADMIN_USER = "admin"
SYSTEM_ADMIN_PASS = "FedR@mp2026!"      # hardcoded system password
DATABASE_PASSWORD = "Db@Secure123"     # hardcoded DB password
LDAP_BIND_DN      = "cn=svc_account,dc=agency,dc=gov"
LDAP_BIND_PASS    = "Ldap$3rvice!"     # hardcoded LDAP service account password

# VIOLATION: Default credentials — CM-6
DEFAULT_API_KEY = "default-api-key-change-me"
INITIAL_ADMIN_PASS = "Admin1234"       # initial/default password never rotated


# =============================================================================
# AC-6 — Least Privilege: overly permissive IAM policies
# =============================================================================

# Over-privileged IAM policy (AWS/cloud IaC)
IAM_POLICY_STAR = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",            # VIOLATION: wildcard action — AC-6
            "Resource": "*",          # VIOLATION: wildcard resource — AC-6
        }
    ]
}

# S3 bucket policy allowing public access — VIOLATION: AC-6
S3_PUBLIC_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Principal": "*",         # VIOLATION: public principal — AC-6
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::sensitive-data-bucket/*",
        }
    ]
}


# =============================================================================
# AU-2 / CMMC 3.3.1 — Audit Logging: sensitive data in logs
# =============================================================================

def log_cui_access(user: str, cui_doc_id: str, ssn: str, clearance: str) -> None:
    # VIOLATION: AU-2 — CUI + PII logged in plain text
    nist_log.info(
        f"CUI_ACCESS user={user} doc={cui_doc_id} ssn={ssn} clearance={clearance}"
    )

def log_authentication(username: str, password: str, result: str) -> None:
    # VIOLATION: AU-2 — password logged in plain text (catastrophic)
    nist_log.info(f"AUTH user={username} password={password} result={result}")


# =============================================================================
# SC-8 / CMMC 3.13.8 — Transmission Confidentiality: cleartext protocols
# =============================================================================

import urllib.request

def fetch_cui_document(doc_id: str, host: str) -> bytes:
    # VIOLATION: SC-8 — CUI transmitted over HTTP — CMMC 3.13.8
    url = f"http://{host}/cui/documents/{doc_id}"
    with urllib.request.urlopen(url) as r:
        return r.read()

def send_pii_to_partner(pii_data: dict, ftp_host: str, ftp_user: str, ftp_pass: str) -> None:
    # VIOLATION: SC-8 — PII sent via FTP (cleartext)
    import ftplib
    ftp = ftplib.FTP(ftp_host)
    ftp.login(ftp_user, ftp_pass)
    # transfer data — cleartext protocol
    ftp.quit()


# =============================================================================
# SC-13 / CMMC 3.13.10 — Cryptographic Protection: weak algorithms
# =============================================================================

def hash_cui_document(content: bytes) -> str:
    # VIOLATION: SC-13 — MD5 used for integrity check (not FIPS-approved for this)
    return hashlib.md5(content).hexdigest()

def encrypt_pii_weak(pii: str, key: str) -> bytes:
    # VIOLATION: SC-13 — DES/RC4 are not FIPS-approved (simulated)
    # In real code: from Crypto.Cipher import DES
    return pii.encode()  # simulated

def sign_document_weak(data: bytes) -> bytes:
    # VIOLATION: SC-13 — SHA1 not approved for digital signatures in federal context
    return hashlib.sha1(data).digest()


# =============================================================================
# SC-28 / CMMC 3.13.10 — Protection at Rest: PII/CUI stored in plaintext
# =============================================================================

# VIOLATION: CUI stored as plaintext in environment / constants
CUI_STORAGE = {
    "contractor_ssn": "678-90-1234",
    "clearance_level": "SECRET",
    "facility_clearance": "TS/SCI",
    "contract_number": "N00014-26-C-0001",   # DoD contract number
    "cage_code": "1ABC2",                     # CAGE code
    "duns": "123456789",                      # DUNS number
}

def write_cui_plaintext(cui_data: dict, filepath: str) -> None:
    # VIOLATION: SC-28 — CUI written to disk unencrypted
    import json
    with open(filepath, 'w') as f:
        json.dump(cui_data, f)


# =============================================================================
# SI-10 — Input Validation: injection vulnerabilities on government systems
# =============================================================================

def agency_lookup(agency_name: str) -> dict:
    import sqlite3
    conn = sqlite3.connect("/var/gov/agencies.db")
    cur = conn.cursor()
    # VIOLATION: SI-10 — SQL injection on government system — CWE-089
    query = f"SELECT * FROM agencies WHERE name = '{agency_name}'"
    cur.execute(query)
    return dict(cur.fetchone() or {})

def run_compliance_scan(target: str) -> str:
    # VIOLATION: SI-10 — command injection — CWE-078
    result = subprocess.run(
        f"nmap -sV {target}",
        shell=True, capture_output=True, text=True
    )
    return result.stdout


# =============================================================================
# CA-7 — Continuous Monitoring: no audit trail for sensitive ops
# =============================================================================

class SensitiveDataAccessor:
    """Accesses classified/CUI data with no monitoring trail."""

    def read_classified(self, doc_id: str, user_id: int) -> dict:
        # VIOLATION: CA-7 — no audit event generated for classified data access
        return {"doc_id": doc_id, "content": "CLASSIFIED CONTENT"}

    def modify_access_control(self, user_id: int, new_role: str) -> None:
        # VIOLATION: CA-7 — privilege change not audited
        pass  # no logging, no audit trail

    def delete_record(self, record_id: str) -> None:
        # VIOLATION: CA-7 — deletion not audited (no WORM/immutable log)
        pass


# =============================================================================
# CMMC 3.5.3 — MFA: services that bypass or skip MFA
# =============================================================================

def admin_login_no_mfa(username: str, password: str) -> str:
    # VIOLATION: CMMC 3.5.3 — admin access without MFA
    if username == SYSTEM_ADMIN_USER and password == SYSTEM_ADMIN_PASS:
        return "admin_session_token_no_mfa"
    return ""

def api_key_only_auth(api_key: str) -> bool:
    # VIOLATION: CMMC 3.5.3 — single-factor auth for privileged API
    return api_key == DEFAULT_API_KEY


# =============================================================================
# DEAD CODE — not reachable from any entry point
# =============================================================================

def dead_code_backdoor() -> None:
    # NOT REACHABLE
    subprocess.run("cat /etc/passwd", shell=True)
    nist_log.critical(f"BACKDOOR: admin={SYSTEM_ADMIN_PASS}")
