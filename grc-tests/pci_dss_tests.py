# Copyright © 2026 Sthenos Security. All rights reserved.
"""
GRC Standards Test Suite — PCI-DSS
====================================
Tests for Payment Card Industry Data Security Standard compliance.
All findings here should map to PCI-DSS controls.

PCI-DSS v4.0 Controls exercised:
  Req 2  — Secure configurations
  Req 3  — Protect stored account data
  Req 4  — Protect cardholder data in transit
  Req 6  — Secure systems and software (CWE)
  Req 7  — Restrict access
  Req 8  — Identify users and authenticate
  Req 10 — Log and monitor
"""

import hashlib
import base64

# =============================================================================
# PCI Req 3.3 — Do not retain sensitive authentication data (SAD)
# SAD = full PAN, CVV/CVC, PIN, magnetic stripe data
# =============================================================================

# VIOLATION: Full PAN stored in plaintext — PCI Req 3.4
class PaymentProcessor:
    def __init__(self):
        # VIOLATION: PANs stored unencrypted in memory/attribute
        self.stored_cards = [
            {"pan": "4532015112830366", "cvv": "737", "expiry": "12/26", "name": "John Smith"},
            {"pan": "5425233430109903", "cvv": "819", "expiry": "08/27", "name": "Jane Doe"},
            {"pan": "374251018720955",  "cvv": "1234", "expiry": "03/28", "name": "Bob Jones"},
        ]

    def store_transaction(self, pan: str, cvv: str, amount: float, merchant_id: str) -> dict:
        # VIOLATION: CVV stored post-authorization — PCI Req 3.3.1 (never store CVV)
        transaction = {
            "merchant_id": merchant_id,
            "pan": pan,               # VIOLATION: full PAN retained
            "cvv": cvv,               # VIOLATION: CVV must NEVER be stored
            "amount": amount,
            "pan_last4": pan[-4:],
        }
        # VIOLATION: PAN logged — PCI Req 3.4 / Req 10.3
        print(f"[AUDIT] Transaction: PAN={pan}, CVV={cvv}, Amount={amount}")
        return transaction

    def export_cardholders(self) -> list:
        # VIOLATION: Full PAN returned in export — no masking
        return self.stored_cards

    def weak_pan_encryption(self, pan: str) -> str:
        # VIOLATION: MD5 used to "encrypt" PAN — PCI Req 3.5 (must use strong crypto)
        return hashlib.md5(pan.encode()).hexdigest()


# =============================================================================
# PCI Req 4.2 — Never send PANs over unprotected communications
# =============================================================================

import urllib.request

def send_payment_unencrypted(pan: str, amount: float, endpoint: str) -> None:
    # VIOLATION: Sending PAN over HTTP (not HTTPS) — PCI Req 4.2.1
    url = f"http://{endpoint}/charge?pan={pan}&amount={amount}"
    urllib.request.urlopen(url)

def log_payment_to_email(pan: str, amount: float) -> None:
    # VIOLATION: PAN in email body — unencrypted channel — PCI Req 4.2
    email_body = f"Payment received: Card {pan}, Amount: ${amount}"
    # simulated email send
    print(f"EMAIL: {email_body}")


# =============================================================================
# PCI Req 6 — Develop and maintain secure systems (maps to CWEs)
# =============================================================================

def get_payment_by_id(payment_id: str) -> dict:
    import sqlite3
    conn = sqlite3.connect("/var/app/payments.db")
    cur = conn.cursor()
    # VIOLATION: SQL injection — PCI Req 6.3.1 / CWE-089
    query = f"SELECT * FROM payments WHERE id = '{payment_id}'"
    cur.execute(query)
    return dict(cur.fetchone() or {})


def render_receipt(transaction_id: str, card_name: str) -> str:
    # VIOLATION: XSS — PCI Req 6.3.1 / CWE-079
    return f"<html><body>Receipt for {card_name}: txn {transaction_id}</body></html>"


# =============================================================================
# PCI Req 8 — Identify users and authenticate access (weak auth)
# =============================================================================

# VIOLATION: Hardcoded admin credentials — PCI Req 8.3 / CWE-798
PAYMENT_ADMIN_USER = "admin"
PAYMENT_ADMIN_PASS = "Payment@123"     # hardcoded credential
API_KEY_PROD       = "pk_live_4eC39HqLyjWDarjtT1zdp7dc"  # production key

def authenticate_admin(username: str, password: str) -> bool:
    # VIOLATION: Non-timing-safe comparison — PCI Req 8.3.6 / CWE-208
    return username == PAYMENT_ADMIN_USER and password == PAYMENT_ADMIN_PASS

def generate_session_token(user_id: int) -> str:
    # VIOLATION: Predictable session token — PCI Req 8.3.9
    import time
    return base64.b64encode(f"{user_id}:{int(time.time())}".encode()).decode()


# =============================================================================
# PCI Req 10 — Log and monitor all access (logging PAN is a violation)
# =============================================================================

import logging
pci_logger = logging.getLogger("payments")

def log_card_authorization(pan: str, result: str, merchant: str) -> None:
    # VIOLATION: Full PAN in log — PCI Req 10.3 prohibits logging raw PAN
    pci_logger.info(f"Auth result={result} pan={pan} merchant={merchant}")

def log_refund(pan: str, cvv: str, amount: float) -> None:
    # VIOLATION: CVV in log — must never be stored or logged anywhere
    pci_logger.warning(f"Refund: pan={pan} cvv={cvv} amount={amount}")


# =============================================================================
# DEAD CODE — cardholder data handling but not reachable
# =============================================================================

def dead_code_card_dump() -> None:
    # NOT REACHABLE — unreachable card dump routine
    dead_cards = [
        "4916338506082832",
        "4532015112830366",
        "5425233430109903",
    ]
    for card in dead_cards:
        print(f"Card: {card}")
