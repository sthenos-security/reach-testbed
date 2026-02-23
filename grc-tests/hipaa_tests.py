"""
GRC Standards Test Suite — HIPAA
==================================
Tests for Health Insurance Portability and Accountability Act compliance.
All findings map to HIPAA Security Rule and Privacy Rule controls.

HIPAA Controls exercised:
  164.312(a)(2)(i) — Unique user identification
  164.312(b)       — Audit controls (PHI in logs)
  164.312(c)       — Integrity
  164.312(d)       — Authentication
  164.312(e)(1)    — Transmission security (PHI over HTTP)
  164.514          — De-identification
"""

import hashlib
import logging
import os

hipaa_log = logging.getLogger("hipaa")

# =============================================================================
# HIPAA 164.312(b) — Audit Controls: PHI must not appear in raw logs
# =============================================================================

def log_patient_access(mrn: str, ssn: str, diagnosis: str, user_id: str) -> None:
    # VIOLATION: PHI (MRN, SSN, diagnosis) in plain log — HIPAA 164.312(b)
    hipaa_log.info(
        f"PATIENT_ACCESS user={user_id} mrn={mrn} ssn={ssn} diagnosis={diagnosis}"
    )

def log_prescription_access(patient_name: str, dea_number: str, drug: str) -> None:
    # VIOLATION: Patient name + DEA# + drug in log — PHI exposure
    hipaa_log.warning(f"RX_ACCESS: patient={patient_name} dea={dea_number} drug={drug}")


# =============================================================================
# HIPAA 164.312(e)(1) — Transmission Security: PHI over HTTP
# =============================================================================

import urllib.request
import json

def send_phi_over_http(patient_record: dict, endpoint: str) -> None:
    # VIOLATION: PHI transmitted over HTTP — HIPAA 164.312(e)(1)
    url = f"http://{endpoint}/patient"
    data = json.dumps(patient_record).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    urllib.request.urlopen(req)

def fetch_phi_unencrypted(patient_id: str, host: str) -> dict:
    # VIOLATION: PHI fetched over HTTP — HIPAA 164.312(e)
    url = f"http://{host}/api/patient/{patient_id}?include=ssn,diagnosis,mrn"
    with urllib.request.urlopen(url) as r:
        return json.loads(r.read())


# =============================================================================
# HIPAA 164.514 — De-identification: PHI stored/handled insecurely
# =============================================================================

class EHRSystem:
    """Electronic Health Record system with intentional HIPAA violations."""

    # VIOLATION: PHI hardcoded as class attributes — 164.514 (impermissible use)
    SAMPLE_PATIENTS = [
        {
            "mrn": "MRN-2026-001234",
            "name": "Patricia Highsmith",
            "dob": "1959-04-03",
            "ssn": "234-56-7891",
            "diagnosis": "Bipolar I Disorder",       # sensitive mental health PHI
            "medication": "Lithium Carbonate 300mg",
            "insurance_id": "BCBS-1234567890",
            "provider_npi": "1234567890",
        },
        {
            "mrn": "MRN-2026-005678",
            "name": "Raymond Carver",
            "dob": "1963-11-22",
            "ssn": "345-67-8902",
            "diagnosis": "HIV/AIDS",                 # sensitive PHI — HIPAA special category
            "medication": "Tenofovir/Emtricitabine",
            "insurance_id": "UHC-9876543210",
        },
    ]

    def export_phi_unprotected(self) -> list:
        # VIOLATION: Full PHI exported without de-identification — 164.514
        return self.SAMPLE_PATIENTS

    def store_phi_weak_crypto(self, phi: dict) -> str:
        # VIOLATION: PHI "encrypted" with MD5 — not HIPAA-compliant encryption
        import json
        return hashlib.md5(json.dumps(phi).encode()).hexdigest()

    def query_by_diagnosis(self, diagnosis: str) -> list:
        import sqlite3
        conn = sqlite3.connect("/var/ehr/patients.db")
        cur = conn.cursor()
        # VIOLATION: SQL injection on PHI query + CWE-089 — HIPAA 164.312(c)
        query = f"SELECT * FROM patients WHERE diagnosis LIKE '%{diagnosis}%'"
        cur.execute(query)
        return [dict(r) for r in cur.fetchall()]

    def get_patient_url(self, mrn: str, diagnosis: str) -> str:
        # VIOLATION: PHI in URL — logged by web servers — HIPAA 164.312(b)
        return f"https://ehr.internal/patients/{mrn}?diagnosis={diagnosis}&include_ssn=true"


# =============================================================================
# HIPAA 164.312(d) — Authentication: Weak or shared credentials
# =============================================================================

# VIOLATION: Hardcoded EHR admin credentials — HIPAA 164.312(a)(2)(i)
EHR_ADMIN_USER = "ehr_admin"
EHR_ADMIN_PASS = "Hosp1tal@dmin"     # hardcoded credential
SHARED_CLINICIAN_PASS = "Cl1nic@l1"  # shared password across users — HIPAA violation

def ehr_login(username: str, password: str) -> bool:
    # VIOLATION: Shared/hardcoded password, non-timing-safe compare
    return password in [EHR_ADMIN_PASS, SHARED_CLINICIAN_PASS]


# =============================================================================
# PHI in comments / error messages — audit trail exposure
# =============================================================================

def process_insurance_claim(patient_ssn: str, mrn: str, diagnosis_code: str) -> dict:
    """Process an insurance claim for patient."""
    if not patient_ssn:
        # VIOLATION: PHI (MRN) in exception message — logged by error handlers
        raise ValueError(f"Missing SSN for patient MRN={mrn} diagnosis={diagnosis_code}")

    return {
        "claim_id": f"CLM-{mrn[-6:]}",
        "status": "submitted",
        # VIOLATION: PHI returned in API response without need — 164.514
        "patient_ssn": patient_ssn,
        "mrn": mrn,
        "diagnosis_code": diagnosis_code,
    }


# =============================================================================
# HIPAA — Dead code (not reachable, should show NOT_REACHABLE)
# =============================================================================

def dead_phi_exfil() -> None:
    # NOT REACHABLE — dead code data exfiltration
    dead_patients = {
        "patient": "John Doe",
        "ssn": "999-00-0001",
        "hiv_status": "positive",
        "mrn": "MRN-DEAD-999999",
    }
    hipaa_log.critical(f"LEAKED PHI: {dead_patients}")
