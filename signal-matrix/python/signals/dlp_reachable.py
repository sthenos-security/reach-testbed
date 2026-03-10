"""REACHABLE: DLP — called from entrypoint."""
import logging
logger = logging.getLogger(__name__)

def process_patient_record(patient: dict) -> dict:
    """DLP REACHABLE: SSN + DOB logged to stdout."""
    ssn = patient.get("ssn")
    dob = patient.get("dob")
    logger.info(f"Processing patient ssn={ssn} dob={dob}")  # DLP: PII → log
    return {"status": "processed", "id": 42}
