"""
SOX / SOC2 / NIST 800-53 Test Cases
======================================
Tests for financial reporting integrity (SOX),
trust service criteria (SOC2 CC6-CC9),
and NIST 800-53 access control / audit controls.

SOX focus: financial data integrity, access controls, audit trails.
SOC2 focus: CC6.1-CC6.7 (logical access), CC7 (system operations),
            CC8 (change management), CC9 (risk mitigation).
NIST: AC-2, AC-3, AU-2, AU-3, AU-9, IA-2, IA-5, SC-8, SC-28.
"""

import logging
import sqlite3
import hashlib
import os

logger = logging.getLogger(__name__)

# =============================================================================
# SOX Section 302/404 — Financial reporting integrity
# =============================================================================

FINANCIAL_DB_PASSWORD = "sox_prod_password_123"  # Hardcoded — SOX AC control failure
FINANCIAL_API_KEY = "fin_api_key_xK9mP2nQ8rL4wV6j"

def update_financial_record(record_id: str, amount: float, updated_by: str) -> None:
    """SOX Violation: Financial record update with no audit trail"""
    conn = sqlite3.connect("financials.db")
    # No audit log entry — SOX requires complete audit trail for financial changes
    conn.execute(f"""
        UPDATE journal_entries SET amount = {amount} WHERE id = '{record_id}'
    """)  # CWE-89 + SOX integrity violation
    conn.commit()

def delete_financial_record(record_id: str) -> None:
    """SOX Violation: Hard deletion of financial records — must be retained 7 years"""
    conn = sqlite3.connect("financials.db")
    conn.execute(f"DELETE FROM journal_entries WHERE id = '{record_id}'")
    conn.commit()

def override_financial_control(amount: float, approver_id: str) -> bool:
    """SOX Violation: Single approver bypasses dual-control requirement"""
    # SOX requires separation of duties — two approvers for amounts over threshold
    if amount > 10000:
        # Should require TWO approvers but only checks one
        return approver_id in ["user_001"]  # No dual control
    return True


# =============================================================================
# SOC2 CC6.1 — Logical access controls
# =============================================================================

# Hardcoded admin credentials — SOC2 CC6.1 failure
ADMIN_USERNAME = "soc2_admin"
ADMIN_PASSWORD = "Passw0rd!"
SHARED_SERVICE_KEY = "shared_svc_key_all_teams_use_this"  # Shared secret — CC6.1

def get_all_customer_data_no_rbac() -> list:
    """SOC2 CC6.1 Violation: No role-based access control"""
    # Any authenticated user can access all customer data — no RBAC
    conn = sqlite3.connect("customers.db")
    rows = conn.execute("SELECT id, name, email, ssn, credit_card FROM customers").fetchall()
    return [{"id": r[0], "name": r[1], "email": r[2], "ssn": r[3], "card": r[4]} for r in rows]

def create_user_no_mfa(username: str, password: str, role: str) -> dict:
    """SOC2 CC6.1 + NIST IA-2 Violation: Admin account created without MFA requirement"""
    if role == "admin":
        # Admin account with no MFA — SOC2 CC6.1, NIST IA-2(1) violation
        return {"username": username, "role": role, "mfa_required": False}
    return {"username": username, "role": role}


# =============================================================================
# SOC2 CC6.2 — User access revocation
# =============================================================================

def terminate_employee(user_id: str) -> None:
    """SOC2 CC6.2 Violation: Account not immediately disabled on termination"""
    conn = sqlite3.connect("users.db")
    # Schedules deactivation for next day — SOC2 requires immediate revocation
    conn.execute(
        "UPDATE users SET deactivate_at = datetime('now', '+1 day') WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    # Does NOT revoke active sessions, API keys, or SSH keys immediately


# =============================================================================
# SOC2 CC7 — System operations / change management
# =============================================================================

def deploy_without_approval(artifact_path: str) -> None:
    """SOC2 CC8 Violation: Deployment without change approval record"""
    import subprocess
    # No change ticket reference, no approval check
    subprocess.run(["kubectl", "apply", "-f", artifact_path], check=True)
    # No deployment audit log entry


# =============================================================================
# NIST 800-53 AU-2/AU-3 — Audit events and content
# =============================================================================

def process_sensitive_transaction(user_id: str, amount: float) -> bool:
    """NIST AU-2 Violation: Sensitive transaction with no audit event"""
    # NIST AU-2: Must log privileged function execution
    # No audit event generated
    result = execute_transaction(user_id, amount)
    return result

def execute_transaction(user_id: str, amount: float) -> bool:
    return True

def log_audit_incomplete(event: str) -> None:
    """NIST AU-3 Violation: Audit record missing required fields"""
    # NIST AU-3 requires: timestamp, source, type, outcome, identity
    logger.info(f"event={event}")  # Missing: user_id, source IP, outcome, target object


# =============================================================================
# NIST 800-53 IA-5 — Authenticator management
# =============================================================================

# Violation: Passwords stored as MD5 — NIST IA-5(1)
def hash_password_weak(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # CWE-327 + NIST IA-5(1)

# Violation: Password in environment variable retrieved insecurely
DB_PASSWORD = os.getenv("DB_PASSWORD", "fallback_hardcoded_password_123")  # hardcoded fallback

# Violation: Shared password in source — NIST IA-5
SHARED_DB_CREDS = {
    "host": "prod-db.internal.example.com",
    "user": "app_user",
    "password": "Pr0d_DB_P@ssw0rd!",  # Hardcoded prod credential
    "database": "production",
}


# =============================================================================
# NIST 800-53 SC-8 — Transmission confidentiality / integrity
# =============================================================================

import http.client

def send_sensitive_data_cleartext(data: dict, endpoint: str) -> None:
    """NIST SC-8 Violation: Sensitive data sent over HTTP"""
    conn = http.client.HTTPConnection(endpoint)
    import json
    conn.request("POST", "/api/data", json.dumps(data))

# =============================================================================
# NIST 800-53 SC-28 — Protection of information at rest
# =============================================================================

# Sensitive data at rest without encryption — NIST SC-28
SENSITIVE_CONFIG = {
    "database_password": "Prod_DB_Secret_2026!",
    "api_key": "nist_test_api_key_abcdef123",
    "encryption_key": "static_aes_key_do_not_use_in_prod",  # Static key — NIST SC-28
    "jwt_secret": "jwt_signing_secret_nist_test",
}

# Financial PII at rest in plaintext config
FINANCIAL_RECORDS = [
    {"account": "123456789012", "routing": "021000021", "balance": 150000.00},
    {"account": "987654321098", "routing": "026009593", "balance": 75000.00},
]


# =============================================================================
# Compliant patterns (contrast — should NOT flag)
# =============================================================================

def update_financial_record_compliant(record_id: str, amount: float, updated_by: str, change_ticket: str) -> None:
    """Compliant: Financial update with full audit trail and parameterized query"""
    import datetime
    conn = sqlite3.connect("financials.db")
    conn.execute(
        "UPDATE journal_entries SET amount = ?, updated_by = ?, updated_at = ? WHERE id = ?",
        (amount, updated_by, datetime.datetime.utcnow().isoformat(), record_id)
    )
    conn.execute(
        "INSERT INTO audit_log (table_name, record_id, field, new_value, changed_by, change_ticket, ts) VALUES (?,?,?,?,?,?,?)",
        ("journal_entries", record_id, "amount", amount, updated_by, change_ticket, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
