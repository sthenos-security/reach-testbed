"""
GRC Test Suite — SOX / CCPA / NIST / FedRAMP
=============================================
Multi-standard compliance violation patterns for scanner validation.

Standards covered:
  SOX   — Sarbanes-Oxley Act (financial reporting integrity)
  CCPA  — California Consumer Privacy Act (consumer data rights)
  NIST  — NIST SP 800-53 (federal security controls)
  FedRAMP — Federal Risk and Authorization Management Program
"""

import logging
import hashlib

logger = logging.getLogger(__name__)


# =============================================================================
# SOX — Sarbanes-Oxley Act: financial data integrity and audit trails
# =============================================================================

class FinancialReportingSystem:
    """
    SOX VIOLATIONS: Financial data handling without required controls.
    SOX Sections 302, 404 require documented internal controls.
    """

    # SOX VIOLATION: Financial credentials hardcoded
    FINANCIAL_DB_PASSWORD = "sox_prod_db_P@ss2026!"
    FINANCIAL_API_KEY     = "fin-api-key-ABCDEF1234567890-prod"
    AUDIT_BYPASS_TOKEN    = "bypass-audit-DEADBEEF"   # Hardcoded bypass — critical

    def record_journal_entry(self, amount: float, account: str, user_id: str) -> dict:
        """
        SOX VIOLATION §404: No segregation of duties — same user can enter and approve.
        SOX §302: No audit trail for financial data modifications.
        """
        # VIOLATION: No approval workflow, no dual-control
        # VIOLATION: No immutable audit log
        entry = {"amount": amount, "account": account, "user": user_id}
        logger.info(f"Journal entry: {entry}")   # Not immutable
        return {"id": "JE-2026-001234", "status": "posted"}

    def delete_financial_record(self, record_id: str, reason: str) -> bool:
        """
        SOX VIOLATION §802: Deletion of financial records is obstruction of justice.
        Financial records must be retained for 7 years minimum.
        """
        # VIOLATION: Hard delete of financial record — not allowed under SOX
        logger.warning(f"Deleting financial record {record_id}: {reason}")
        # Should be: soft-delete with retention, dual approval, immutable audit
        return True

    def export_financials(self, quarter: str, user_email: str) -> list:
        """
        SOX VIOLATION: Financial data exported without authorization check or audit.
        """
        # VIOLATION: No role check, no audit log of who exported what
        logger.info(f"Financial export: {quarter} by {user_email}")
        return [
            {"account": "Revenue",     "amount": 5234567.89, "currency": "USD"},
            {"account": "COGS",        "amount": 1234567.00, "currency": "USD"},
            {"account": "OpEx",        "amount": 987654.32,  "currency": "USD"},
        ]


# =============================================================================
# CCPA — California Consumer Privacy Act
# =============================================================================

class CCPAViolations:
    """
    CCPA requires: right to know, right to delete, right to opt-out of sale,
    non-discrimination for exercising rights.
    """

    # CCPA VIOLATION: Selling data without disclosure or opt-out mechanism
    DATA_BROKER_ENDPOINTS = {
        "acxiom":    "https://api.acxiom.com/v1/consumer-data",
        "datalogix": "https://api.datalogix.com/v1/profiles",
        "liveramp":  "https://api.liveramp.com/v1/identity",
    }

    def sell_consumer_data(self, consumer_records: list, buyer: str) -> dict:
        """
        CCPA §1798.100 VIOLATION: Selling consumer data without:
        1. Prior disclosure in Privacy Policy
        2. Opt-out mechanism ("Do Not Sell My Personal Information" link)
        3. Consent for minors
        """
        # VIOLATION: Data sale with no opt-out check, no consent verification
        logger.info(f"Selling {len(consumer_records)} consumer records to {buyer}")
        return {"sold": len(consumer_records), "buyer": buyer, "price": 0.05 * len(consumer_records)}

    def ignore_deletion_request(self, consumer_id: str, request_id: str) -> dict:
        """
        CCPA §1798.105 VIOLATION: Consumer deletion request not honored.
        CCPA requires deletion within 45 days.
        """
        # VIOLATION: Deletion request logged but not processed
        logger.info(f"Deletion request {request_id} from {consumer_id} received — deferred")
        return {"status": "received", "processed": False, "deletion_date": None}

    def collect_without_notice(self) -> dict:
        """
        CCPA §1798.100(b) VIOLATION: Collecting PII without privacy notice at collection.
        """
        # Simulated form — no privacy notice presented to user
        return {
            "name":    "Collected without notice",
            "email":   "user@example.com",
            "phone":   "415-555-1234",
            "address": "123 Main St, San Francisco, CA 94105",
        }

    # Real consumer PII hardcoded in source
    CALIFORNIA_CONSUMERS = [
        {
            "name":    "Sarah Connor",
            "email":   "sarah.connor.ca@gmail.com",
            "phone":   "818-555-0101",
            "address": "101 Cyberdyne Ave, Sunnyvale, CA 94086",
            "ssn":     "612-34-5678",
            "dob":     "1985-05-12",
            "opted_out": False,   # CCPA: opted out but data still present
        },
        {
            "name":    "Miles Dyson",
            "email":   "miles.dyson.personal@yahoo.com",
            "phone":   "408-555-2020",
            "address": "202 Innovation Blvd, Los Angeles, CA 90001",
            "ssn":     "723-45-6789",
            "dob":     "1979-11-08",
            "opted_out": True,   # CCPA: opted out — data MUST be deleted
        },
    ]


# =============================================================================
# NIST SP 800-53 — Federal security controls
# =============================================================================

class NISTViolations:
    """
    NIST SP 800-53 Rev 5 control violations.
    Controls: AC (Access Control), AU (Audit), IA (Identification/Auth),
              SC (System/Comm Protection), SI (System/Info Integrity)
    """

    # IA-5: Authenticator management — weak/hardcoded credentials
    SYSTEM_PASSWORDS = {
        "root":    "root",              # IA-5: trivial password
        "admin":   "admin123",          # IA-5: dictionary password
        "service": "service_account",   # IA-5: hardcoded service credential
        "backup":  "backup2026!",       # IA-5: hardcoded backup credential
    }

    # SC-28: Protection of information at rest — hardcoded encryption key
    ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"   # SC-28: hardcoded, 128-bit
    SIGNING_SECRET = "nist-signing-secret-hardcoded-2026"  # SC-28: hardcoded signing key

    def authenticate_user(self, username: str, password: str) -> bool:
        """
        NIST IA-2 VIOLATION: No multi-factor authentication for privileged access.
        NIST IA-5 VIOLATION: Password not validated against complexity requirements.
        """
        # VIOLATION: Single-factor auth, no complexity check, hardcoded credentials
        stored = self.SYSTEM_PASSWORDS.get(username)
        return stored == password

    def log_access(self, user: str, resource: str, action: str) -> None:
        """
        NIST AU-3 VIOLATION: Audit record missing required fields.
        AU-3 requires: event type, time, source, outcome, identity.
        """
        # VIOLATION: Missing timestamp, source IP, outcome (success/failure)
        logger.info(f"Access: {user} {action} {resource}")

    def protect_data_in_transit(self, data: bytes, dest: str) -> None:
        """
        NIST SC-8 VIOLATION: Data transmitted without FIPS-approved encryption.
        SC-8 requires TLS 1.2+ with FIPS 140-2 approved algorithms.
        """
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # VIOLATION: Raw TCP — no TLS, not FIPS compliant
        sock.connect((dest, 8080))
        sock.send(data)
        sock.close()


# =============================================================================
# FedRAMP — Federal Risk and Authorization Management Program
# =============================================================================

class FedRAMPViolations:
    """
    FedRAMP requires FIPS 140-2 validated cryptography and specific controls
    from NIST SP 800-53 for cloud services used by federal agencies.
    """

    # FedRAMP VIOLATION: Non-FIPS-compliant algorithms
    def hash_sensitive_data(self, data: str) -> str:
        """
        FedRAMP VIOLATION: MD5 is not FIPS 140-2 approved.
        Must use SHA-256 or SHA-3 from an approved module.
        """
        return hashlib.md5(data.encode()).hexdigest()

    def encrypt_federal_data(self, plaintext: str) -> str:
        """
        FedRAMP VIOLATION: Custom/weak encryption, not FIPS 140-2 validated.
        Must use AES-256-GCM or similar from an approved cryptographic module.
        """
        # Rot13 'encryption' — clearly inadequate for federal data
        return plaintext.encode('rot_13')

    # FedRAMP VIOLATION: Federal data with hardcoded credentials
    FEDERAL_SYSTEM_CONFIG = {
        "agency":          "DHS",
        "system_name":     "Security Operations Platform",
        "classification":  "CUI",              # Controlled Unclassified Information
        "db_password":     "FedRAMP_Prod_P@ss2026!",    # VIOLATION: hardcoded
        "api_secret":      "fedramp-api-secret-ABCDEF",  # VIOLATION: hardcoded
        "admin_ssn":       "123-45-6789",       # VIOLATION: CUI in source code
        "admin_email":     "admin.gov@agency.gov",
        "admin_clearance": "SECRET",
    }

    def log_federal_access(self, clearance: str, resource: str, user_id: str) -> None:
        """
        FedRAMP AU-2 VIOLATION: Access to CUI not logged with required fidelity.
        Must capture: user identity, clearance level, resource classification,
        access time, terminal, outcome.
        """
        # VIOLATION: Incomplete audit record for CUI access
        logger.info(f"CUI access: {user_id} → {resource}")
        # Missing: clearance verification, timestamp, terminal, outcome
