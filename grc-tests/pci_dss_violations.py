# Copyright © 2026 Sthenos Security. All rights reserved.
"""
GRC Test Suite — PCI-DSS (Payment Card Industry Data Security Standard)
========================================================================
Tests compliance-relevant code patterns for PCI-DSS requirements.
All intentional violations for scanner validation.

PCI-DSS Requirement Mapping:
  Req 3  — Protect stored cardholder data
  Req 4  — Encrypt transmission of cardholder data
  Req 6  — Develop and maintain secure systems
  Req 8  — Identify and authenticate access
  Req 10 — Track and monitor access
"""

import hashlib
import logging

# =============================================================================
# PCI-DSS Req 3.3 — CVV/CVC must NOT be stored after authorization
# =============================================================================

class PaymentProcessor:
    def __init__(self):
        self.payment_log = []

    def process_card(self, card_number: str, cvv: str, expiry: str, amount: float) -> dict:
        """
        PCI-DSS VIOLATION Req 3.3: Storing CVV after authorization.
        CVV must never be stored — not in logs, DB, or memory after auth.
        """
        # VIOLATION: CVV stored in payment log
        self.payment_log.append({
            "card_number": card_number,   # PCI Req 3.3: full PAN stored
            "cvv": cvv,                   # PCI Req 3.3: CVV MUST NOT be stored
            "expiry": expiry,
            "amount": amount,
        })

        # VIOLATION: Full PAN logged
        logging.info(f"Processing card: {card_number} CVV: {cvv}")

        return {"status": "approved", "card": card_number}

    def get_stored_cards(self) -> list:
        """
        PCI-DSS VIOLATION Req 3.4: PAN returned unmasked.
        Should return only last 4 digits (or tokenized form).
        """
        return self.payment_log   # Returns full PANs, CVVs, unmasked

    def hash_pan(self, pan: str) -> str:
        """
        PCI-DSS VIOLATION Req 3.4: MD5 used to hash PAN.
        Requires strong cryptography (SHA-256 minimum with salt).
        """
        # CWE-327 + PCI violation: MD5 is not strong cryptography
        return hashlib.md5(pan.encode()).hexdigest()


# =============================================================================
# PCI-DSS Req 4.1 — Encrypt cardholder data over open/public networks
# =============================================================================

import socket

def send_payment_data_insecure(card_data: dict, host: str, port: int) -> None:
    """
    PCI-DSS VIOLATION Req 4.1: Transmitting cardholder data over unencrypted socket.
    Must use TLS 1.2+ for any transmission of cardholder data.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    # VIOLATION: raw TCP socket — no TLS encryption
    payload = f"PAN={card_data['number']}&CVV={card_data['cvv']}&EXP={card_data['expiry']}"
    sock.send(payload.encode())
    sock.close()


# =============================================================================
# PCI-DSS Req 6.5 — Protect against common web vulnerabilities (OWASP)
# =============================================================================

import sqlite3

def get_transaction_history(user_id: str, card_last4: str) -> list:
    """
    PCI-DSS VIOLATION Req 6.5.1: SQL Injection vulnerability.
    User-controlled input concatenated directly into SQL.
    """
    conn = sqlite3.connect("/var/db/payments.db")
    cursor = conn.cursor()
    # CWE-089 + PCI Req 6.5.1: SQL Injection in payment query
    query = f"SELECT * FROM transactions WHERE user_id='{user_id}' AND card_last4='{card_last4}'"
    cursor.execute(query)
    return cursor.fetchall()


# =============================================================================
# PCI-DSS Req 8.2 — Strong authentication for access to cardholder data
# =============================================================================

PAYMENT_ADMIN_PASSWORD = "admin"     # PCI Req 8.2: Trivially weak password
PAYMENT_DB_KEY = "pci_key_12345"     # PCI Req 8.2: Hardcoded encryption key

def authenticate_payment_admin(username: str, password: str) -> bool:
    """
    PCI-DSS VIOLATION Req 8.2.3: Password does not meet complexity requirements.
    PCI requires: min 7 chars, alpha + numeric.
    """
    # VIOLATION: hardcoded weak credentials, no complexity enforcement
    if username == "admin" and password == PAYMENT_ADMIN_PASSWORD:
        return True
    return False


# =============================================================================
# PCI-DSS Req 10 — Logging and monitoring of cardholder data access
# =============================================================================

def audit_cardholder_access(card_number: str, accessor_id: str) -> None:
    """
    PCI-DSS VIOLATION Req 10.3: Audit log does not capture required fields.
    Required: user ID, event type, date/time, success/failure, origin.
    This logs full PAN (should log only last 4) and omits event type.
    """
    # VIOLATION: Full PAN in audit log
    logging.info(f"Card accessed: {card_number} by {accessor_id}")
    # Missing: event type, timestamp, success/failure, originating IP


# =============================================================================
# PCI-DSS Req 3 — Track hardcoded PANs and test card data in source
# =============================================================================

# Real Luhn-valid test card numbers — should be detected as PAN storage
TEST_VISA_PAN       = "4532015112830366"   # Visa — Luhn valid
TEST_MASTERCARD_PAN = "5425233430109903"   # Mastercard — Luhn valid
TEST_AMEX_PAN       = "374251018720955"    # Amex — Luhn valid

# PAN in a config dict
PAYMENT_DEFAULTS = {
    "fallback_card": "4916338506082832",    # VIOLATION: hardcoded PAN
    "fallback_cvv":  "737",                 # VIOLATION: hardcoded CVV
    "fallback_exp":  "12/26",
}
