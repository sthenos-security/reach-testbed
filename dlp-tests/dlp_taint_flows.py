"""
DLP Taint Flow Tests
=====================
INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
Copyright © 2026 Sthenos Security. Test file only.

Tests REACHABLE's DLP taint tracking — PII flowing INTO sinks:
  - PII → LLM API call  (DLP + AI combined signal)
  - PII → logging sink  (data exposure via logs)
  - PII → external HTTP (exfiltration)
  - PII → transitive data flow (user input → transform → store)

These complement dlp_true_positives.py (static PII presence) by testing
whether the scanner tracks PII *movement* through the call graph.
"""

import logging
import requests
from flask import Flask, request, jsonify

logger = logging.getLogger(__name__)
app = Flask(__name__)

# =============================================================================
# TAINT-01: PII flowing into LLM API call
# DLP + AI combined signal — patient data sent to external LLM
# =============================================================================

@app.route("/api/summarize-patient", methods=["POST"])
def pii_into_llm_reachable():
    """
    CRITICAL: Patient PII (SSN, DOB, medical notes) sent to external LLM.
    DLP taint: user_data → openai API call.
    Violates HIPAA BAA requirements (data leaving covered entity without agreement).
    """
    from openai import OpenAI

    patient = request.json
    # PII fields extracted from request
    ssn        = patient.get("ssn")           # SSN
    dob        = patient.get("dob")           # Date of birth
    diagnosis  = patient.get("diagnosis")     # Medical data
    full_name  = patient.get("name")          # PII

    client = OpenAI()
    # VIOLATION: PII directly in LLM prompt — taint: ssn/dob/diagnosis → LLM API
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{
            "role": "user",
            "content": f"Summarize this patient record: "
                       f"Name={full_name}, SSN={ssn}, DOB={dob}, Diagnosis={diagnosis}"
            # VIOLATION: PII in prompt sent to external API
        }]
    )
    return jsonify({"summary": response.choices[0].message.content})


@app.route("/api/analyze-user", methods=["POST"])
def pii_into_anthropic_reachable():
    """
    VIOLATION: Credit card + email sent to Anthropic API.
    DLP taint: credit_card/email → anthropic.messages.create()
    """
    from anthropic import Anthropic

    data = request.json
    credit_card = data.get("card_number")   # PII: credit card
    email       = data.get("email")         # PII: email
    amount      = data.get("amount")

    client = Anthropic()
    # VIOLATION: payment PII in LLM prompt
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=256,
        messages=[{
            "role": "user",
            "content": f"Analyze this transaction: card={credit_card}, email={email}, amount={amount}"
            # VIOLATION: credit card in LLM prompt
        }]
    )
    return jsonify({"analysis": response.content[0].text})


# =============================================================================
# TAINT-02: PII flowing into logging sink
# =============================================================================

@app.route("/api/register", methods=["POST"])
def pii_into_logs_reachable():
    """
    VIOLATION: SSN and credit card logged at INFO level.
    DLP taint: ssn/credit_card → logger.info() → log file/SIEM
    """
    data = request.json
    user_ssn = data.get("ssn")              # PII: SSN
    card_num = data.get("credit_card")      # PII: credit card
    email    = data.get("email")            # PII: email
    password = data.get("password")         # Secret

    # VIOLATION: PII in log messages
    logger.info(f"New registration: ssn={user_ssn} card={card_num} email={email}")
    logger.debug(f"Full registration payload: {data}")  # VIOLATION: full PII dump
    print(f"Registered user: {user_ssn}, {card_num}")   # VIOLATION: stdout PII leak

    return jsonify({"status": "registered"})


def audit_log_with_pii(user_id: int, action: str, pii_data: dict) -> None:
    """
    VIOLATION: Audit log includes raw PII fields.
    Taint: pii_data → logger.warning()
    """
    # VIOLATION: PII in audit log
    logger.warning(
        f"AUDIT user={user_id} action={action} "
        f"ssn={pii_data.get('ssn')} "         # VIOLATION
        f"dob={pii_data.get('dob')} "         # VIOLATION
        f"card={pii_data.get('credit_card')}"  # VIOLATION
    )


# =============================================================================
# TAINT-03: PII flowing into external HTTP request (exfiltration path)
# =============================================================================

@app.route("/api/sync-crm", methods=["POST"])
def pii_into_external_api_reachable():
    """
    VIOLATION: PII sent to third-party CRM without data processing agreement check.
    DLP taint: ssn/email/phone → requests.post() → external endpoint
    """
    user = request.json
    ssn   = user.get("ssn")
    email = user.get("email")
    phone = user.get("phone")
    name  = user.get("full_name")

    # VIOLATION: PII sent to external CRM endpoint, no encryption check, no DPA
    crm_response = requests.post(
        "https://api.third-party-crm.example.com/contacts",
        json={
            "ssn": ssn,       # VIOLATION
            "email": email,   # VIOLATION
            "phone": phone,   # VIOLATION
            "name": name,
        },
        headers={"Authorization": "Bearer crm-api-key-hardcoded-12345"}  # VIOLATION: hardcoded key
    )
    return jsonify({"crm_id": crm_response.json().get("id")})


# =============================================================================
# TAINT-04: PII transitive flow — user input → transform → store
# Tests multi-hop taint tracking
# =============================================================================

def extract_pii_from_form(form_data: dict) -> dict:
    """Step 1: Extract PII from user form."""
    return {
        "ssn":    form_data.get("social_security_number"),
        "dob":    form_data.get("date_of_birth"),
        "card":   form_data.get("payment_card"),
        "email":  form_data.get("email_address"),
    }


def enrich_pii_record(pii: dict, user_id: int) -> dict:
    """Step 2: Enrich with user ID — PII propagates through."""
    return {**pii, "user_id": user_id, "created_at": "2026-01-01"}


def store_pii_unencrypted(record: dict) -> None:
    """
    Step 3: VIOLATION — PII stored in plaintext DB column.
    DLP taint: pii from extract_pii_from_form → store_pii_unencrypted
    CWE-312: Cleartext storage of sensitive information.
    """
    import sqlite3
    conn = sqlite3.connect("/tmp/users.db")
    # VIOLATION: SSN, card stored as plaintext (no encryption)
    conn.execute(
        "INSERT INTO users (ssn, dob, card, email, user_id) VALUES (?,?,?,?,?)",
        (record["ssn"], record["dob"], record["card"], record["email"], record["user_id"])
    )
    conn.commit()
    conn.close()


@app.route("/api/onboard", methods=["POST"])
def pii_transitive_flow_reachable():
    """
    REACHABLE: Multi-hop PII taint path.
    Taint: request.json → extract_pii_from_form() → enrich_pii_record() → store_pii_unencrypted()
    Scanner must track PII across 3 function calls.
    """
    form_data = request.json
    pii       = extract_pii_from_form(form_data)   # hop 1
    record    = enrich_pii_record(pii, user_id=42)  # hop 2
    store_pii_unencrypted(record)                   # hop 3 — sink
    return jsonify({"status": "onboarded"})


# =============================================================================
# TAINT-05: PII in dead code path — NOT_REACHABLE
# =============================================================================

def dead_code_pii_to_llm():
    """
    NOT_REACHABLE: PII→LLM taint in dead code.
    This function is never called — scanner should mark NOT_REACHABLE.
    """
    from openai import OpenAI
    ssn = "123-45-6789"
    client = OpenAI()
    client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Process SSN: {ssn}"}]
    )
