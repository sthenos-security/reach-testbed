"""
GRC Test Suite — HIPAA (Health Insurance Portability and Accountability Act)
=============================================================================
Tests compliance-relevant code patterns for HIPAA Security Rule requirements.
Intentional PHI exposure patterns for scanner validation.

HIPAA Security Rule mapping:
  §164.312(a)(1) — Access control
  §164.312(a)(2)(iv) — Encryption and decryption
  §164.312(b) — Audit controls
  §164.312(c)(1) — Integrity controls
  §164.312(e)(1) — Transmission security
"""

import logging
import hashlib
from typing import Optional

logger = logging.getLogger(__name__)

# =============================================================================
# HIPAA §164.312(a)(2)(iv) — PHI encryption required
# =============================================================================

class PatientRecord:
    """
    HIPAA VIOLATION: PHI stored and transmitted without encryption.
    All PHI must be encrypted at rest and in transit.
    """

    # VIOLATION: PHI hardcoded in source — SSN, MRN, diagnosis
    DEFAULT_PATIENT = {
        "mrn":       "MRN-2026-001234",
        "name":      "John Smith",
        "ssn":       "123-45-6789",
        "dob":       "1965-08-22",
        "diagnosis": "Type 2 Diabetes, Stage 2 Hypertension",
        "medication": "Metformin 500mg, Lisinopril 10mg",
        "insurance_id": "BCBS-1234567890",
        "phone":     "415-555-9876",
        "email":     "john.smith.patient@gmail.com",
        "address":   "123 Oak Street, San Francisco, CA 94105",
    }

    def __init__(self):
        self.records = {}

    def store_patient(self, patient_id: str, phi: dict) -> None:
        """
        HIPAA VIOLATION §164.312(a)(2)(iv): PHI stored in plain text.
        Must be encrypted at rest.
        """
        # VIOLATION: No encryption before storage
        self.records[patient_id] = phi
        logger.info(f"Stored PHI for patient: {phi.get('name')} SSN: {phi.get('ssn')}")

    def get_patient_phi(self, patient_id: str, accessor: str) -> Optional[dict]:
        """
        HIPAA VIOLATION §164.312(b): Access not audited with required fields.
        §164.312(a)(1): No access control enforcement.
        """
        # VIOLATION: No authorization check — any caller can access any PHI
        record = self.records.get(patient_id)
        # VIOLATION: PHI logged in audit trail
        logger.info(f"PHI accessed: {record}")
        return record

    def export_patient_data(self, patient_id: str) -> str:
        """
        HIPAA VIOLATION §164.312(e)(1): PHI exported without encryption.
        """
        record = self.records.get(patient_id, {})
        # VIOLATION: PHI returned as plain text CSV (no encryption)
        return f"{record.get('name')},{record.get('ssn')},{record.get('diagnosis')},{record.get('medication')}"


# =============================================================================
# HIPAA §164.312(b) — Audit controls: activity must be auditable
# =============================================================================

class EHRSystem:
    """Electronic Health Record System with HIPAA audit violations."""

    def update_diagnosis(self, patient_id: str, new_diagnosis: str, clinician_id: str) -> None:
        """
        HIPAA VIOLATION §164.312(b): Changes to PHI not properly audited.
        Must log: who changed what, when, previous value, new value.
        """
        # VIOLATION: No audit log of PHI change
        self.db_update(patient_id, {"diagnosis": new_diagnosis})
        # Missing: old value, timestamp, clinician credentials

    def bulk_export_phi(self) -> list:
        """
        HIPAA VIOLATION: Mass PHI export without authorization or audit.
        High-severity: entire patient dataset exposed.
        """
        # VIOLATION: No authorization check, no audit, returns all PHI
        return [
            {"mrn": "MRN-001", "name": "Alice Brown",  "ssn": "234-56-7890", "diagnosis": "Hypertension"},
            {"mrn": "MRN-002", "name": "Bob Davis",    "ssn": "345-67-8901", "diagnosis": "Diabetes Type 2"},
            {"mrn": "MRN-003", "name": "Carol Wilson", "ssn": "456-78-9012", "diagnosis": "Asthma, Chronic"},
            {"mrn": "MRN-004", "name": "Dan Martinez", "ssn": "567-89-0123", "diagnosis": "Depression"},
        ]

    def db_update(self, patient_id: str, data: dict) -> None:
        pass  # Simulated


# =============================================================================
# HIPAA §164.312(e)(1) — Transmission security
# =============================================================================

import socket

def transmit_phi_insecure(phi: dict, endpoint: str, port: int = 80) -> None:
    """
    HIPAA VIOLATION §164.312(e)(1): PHI transmitted without encryption.
    All PHI transmission must use TLS. Port 80 = HTTP = unencrypted.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((endpoint, port))
    # VIOLATION: PHI sent over unencrypted HTTP connection
    payload = f"POST /ehr/patient HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n"
    payload += f"ssn={phi.get('ssn')}&name={phi.get('name')}&diag={phi.get('diagnosis')}"
    sock.send(payload.encode())
    sock.close()


# =============================================================================
# HIPAA — Weak cryptography for PHI protection
# =============================================================================

def hash_patient_identifier(patient_id: str) -> str:
    """
    HIPAA VIOLATION: MD5 used for PHI identifier — not FIPS-compliant.
    HIPAA requires FIPS-approved algorithms (SHA-256 minimum).
    """
    # CWE-327 + HIPAA violation: MD5 is not FIPS 140-2 approved
    return hashlib.md5(patient_id.encode()).hexdigest()

def encrypt_phi_weak(phi_string: str) -> str:
    """
    HIPAA VIOLATION: XOR 'encryption' — trivially reversible, not real encryption.
    HIPAA requires AES-256 or equivalent.
    """
    key = 0x42  # Single-byte XOR key — not real encryption
    return bytes([b ^ key for b in phi_string.encode()]).hex()


# =============================================================================
# HIPAA — PHI in error messages / exceptions
# =============================================================================

def process_insurance_claim(patient_ssn: str, diagnosis_code: str, amount: float):
    """
    HIPAA VIOLATION: PHI included in exception messages visible to callers.
    """
    if len(patient_ssn) != 11:
        # VIOLATION: PHI in exception message
        raise ValueError(f"Invalid SSN format for patient {patient_ssn}: diagnosis {diagnosis_code}")

    if amount <= 0:
        raise ValueError(f"Invalid claim amount for SSN {patient_ssn}")

    return {"claim_id": "CLM-2026-001234", "status": "submitted"}


# =============================================================================
# HIPAA — PHI in URL parameters (transmitted unencrypted, logged by web servers)
# =============================================================================

def build_patient_url(patient_id: str, ssn: str, dob: str) -> str:
    """
    HIPAA VIOLATION: PHI passed as URL query parameters.
    URLs are logged by every proxy, CDN, and web server — PHI exposure.
    """
    # VIOLATION: SSN and DOB in URL — logged by every hop
    return f"https://portal.health.example.com/patient?id={patient_id}&ssn={ssn}&dob={dob}"


# =============================================================================
# Real PHI records — hardcoded in source (maximum severity HIPAA violation)
# =============================================================================

# HIPAA VIOLATION: PHI constants hardcoded in source code
SAMPLE_PATIENTS = [
    {
        "mrn": "MRN-2026-001001",
        "name": "Patricia Martinez",
        "ssn": "678-90-1234",
        "dob": "1972-04-15",
        "email": "patricia.martinez.health@gmail.com",
        "phone": "617-555-3421",
        "diagnosis": "Breast Cancer, Stage II",
        "medication": "Tamoxifen 20mg",
        "insurance_id": "AETNA-9876543210",
        "address": "456 Elm Street, Boston, MA 02101",
    },
    {
        "mrn": "MRN-2026-001002",
        "name": "James Thompson",
        "ssn": "789-01-2345",
        "dob": "1955-11-30",
        "email": "james.thompson.patient@yahoo.com",
        "phone": "212-555-7654",
        "diagnosis": "Coronary Artery Disease, NYHA Class III",
        "medication": "Atorvastatin 80mg, Clopidogrel 75mg",
        "insurance_id": "UHC-5432167890",
        "address": "789 Broadway, New York, NY 10001",
    },
]
