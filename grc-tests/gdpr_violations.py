# Copyright © 2026 Sthenos Security. All rights reserved.
"""
GRC Test Suite — GDPR (General Data Protection Regulation)
===========================================================
Tests code patterns relevant to GDPR Articles 5, 17, 25, 32, 33, 83.
Intentional violations for scanner validation.

GDPR Article mapping:
  Art. 5  — Principles of data processing (lawfulness, purpose limitation, minimization)
  Art. 17 — Right to erasure ("right to be forgotten")
  Art. 25 — Data protection by design and by default
  Art. 32 — Security of processing
  Art. 33 — Notification of breach
  Art. 83 — Conditions for fines
"""

import logging

logger = logging.getLogger(__name__)


# =============================================================================
# GDPR Art. 5(1)(b) — Purpose limitation: data only for specified purpose
# =============================================================================

class UserDataProcessor:
    """
    Collects more data than necessary, shares without consent.
    GDPR Art. 5(1)(c): Data minimization principle violated.
    """

    def collect_registration_data(self, form_data: dict) -> dict:
        """
        GDPR VIOLATION Art. 5(1)(c): Collecting excessive data at registration.
        Only email and password required — collecting SSN, income, etc.
        """
        # VIOLATION: Collecting far more than necessary for registration
        user_profile = {
            "email":           form_data.get("email"),
            "password_hash":   form_data.get("password"),   # Should be hashed, not stored
            "name":            form_data.get("name"),
            "phone":           form_data.get("phone"),
            "date_of_birth":   form_data.get("dob"),
            "address":         form_data.get("address"),
            "ssn":             form_data.get("ssn"),         # VIOLATION: SSN not needed for registration
            "income":          form_data.get("income"),      # VIOLATION: income not needed
            "employer":        form_data.get("employer"),    # VIOLATION: employer not needed
            "credit_score":    form_data.get("credit_score"), # VIOLATION: not needed
            "political_views": form_data.get("politics"),    # VIOLATION: special category data
            "religion":        form_data.get("religion"),    # VIOLATION: special category data
            "health_status":   form_data.get("health"),      # VIOLATION: special category data
        }
        return user_profile

    def share_with_third_party(self, user_id: str, partner: str) -> dict:
        """
        GDPR VIOLATION Art. 6: Sharing personal data without legal basis or consent.
        """
        user_data = self.get_user(user_id)
        # VIOLATION: Full PII shared with third party without consent documented in code
        logger.info(f"Sharing user data with {partner}: {user_data}")
        return user_data  # All PII including SSN, health data sent to partner

    def get_user(self, user_id: str) -> dict:
        # Simulated — would query DB
        return {
            "email": "user@example.com",
            "name": "Test User",
            "ssn": "123-45-6789",
            "phone": "555-123-4567",
        }


# =============================================================================
# GDPR Art. 17 — Right to erasure: must be able to delete all PII
# =============================================================================

class UserDeletionService:

    def delete_user(self, user_id: str) -> dict:
        """
        GDPR VIOLATION Art. 17: Deletion incomplete — PII remains in logs and backups.
        Right to erasure requires ALL copies removed, including derived data.
        """
        # Partial deletion — only removes from primary table
        self.db_delete("users", user_id)
        # VIOLATION: PII still in:
        # - audit_logs table (not deleted)
        # - analytics_events (not deleted)
        # - email_archive (not deleted)
        # - backup files (not deleted)
        # - derived profiles in ML model (not deleted)
        logger.info(f"Deleted user {user_id} from primary table only")
        return {"deleted": True, "tables_cleared": ["users"]}  # Incomplete

    def db_delete(self, table: str, record_id: str) -> None:
        pass  # Simulated


# =============================================================================
# GDPR Art. 25 — Data protection by design: default settings must be privacy-preserving
# =============================================================================

class AnalyticsTracker:
    """
    GDPR VIOLATION Art. 25: Privacy-invasive tracking enabled by default.
    Must default to minimum data collection; opt-in for more.
    """

    # VIOLATION: All tracking enabled by default — should default to False
    DEFAULT_SETTINGS = {
        "track_location":    True,    # Precise geolocation — special category
        "track_browsing":    True,    # Full browsing history
        "track_purchases":   True,    # Purchase behavior
        "share_with_ads":    True,    # Third-party ad sharing — requires explicit consent
        "behavioral_profile": True,   # Profile building — requires consent
        "cross_site_tracking": True,  # Cross-context tracking
    }

    def record_event(self, user_id: str, event: str, user_ip: str, user_email: str) -> None:
        """
        GDPR VIOLATION Art. 5(1)(c): Logging full IP + email for analytics.
        IP address and email are personal data — not needed for analytics.
        """
        # VIOLATION: Storing IP + email in analytics events = unnecessary PII
        logger.info(f"Event: user_id={user_id} email={user_email} ip={user_ip} event={event}")

    def export_user_profile(self, user_email: str) -> dict:
        """
        GDPR Art. 20 — Data portability: this is compliant direction,
        but VIOLATION here is returning profile to unauthenticated caller.
        """
        # VIOLATION: No authentication check before returning full profile
        return {
            "email": user_email,
            "browsing_history": ["page1", "page2", "page3"],
            "purchase_history": [{"item": "widget", "amount": 29.99}],
            "location_history": [{"lat": 37.7749, "lng": -122.4194}],
            "ad_profile": {"interests": ["tech", "security"], "income_bracket": "high"},
        }


# =============================================================================
# GDPR Art. 32 — Security of processing: appropriate technical measures
# =============================================================================

import hashlib

def hash_personal_data_weak(pii: str) -> str:
    """
    GDPR VIOLATION Art. 32: Inadequate pseudonymization.
    MD5 without salt is trivially reversible for common PII values.
    """
    # VIOLATION: Unsalted MD5 — not appropriate pseudonymization
    return hashlib.md5(pii.encode()).hexdigest()

# Personal data stored in plain-text config
GDPR_CONFIG = {
    "data_controller": {
        "name":    "Sthenos Security",
        "email":   "dpo@sthenosecurity.com",
        "address": "100 Innovation Drive, San Francisco, CA 94107",
        "phone":   "415-555-0100",
    },
    # VIOLATION: Personal data of employees hardcoded in source
    "dpo_personal": {
        "name":  "Jane Doe",
        "email": "jane.doe.private@gmail.com",
        "ssn":   "234-56-7890",
        "phone": "415-555-1234",
    }
}


# =============================================================================
# GDPR Art. 33 — Breach notification: must detect and report within 72 hours
# =============================================================================

class BreachDetector:

    def log_unauthorized_access(self, user_id: str, accessor_ip: str, pii_fields: list) -> None:
        """
        GDPR VIOLATION Art. 33: Breach events not flagged for 72-hour notification.
        Unauthorized access to PII is a breach that requires DPA notification.
        """
        # VIOLATION: Logged but not flagged as breach — no notification triggered
        logger.warning(f"Unauthorized access: user={user_id} from IP={accessor_ip} fields={pii_fields}")
        # Missing: breach_registry.record(), notification_queue.enqueue()

    def detect_mass_export(self, records_exported: int, user_email: str) -> bool:
        """
        GDPR VIOLATION: Bulk export not treated as potential breach.
        """
        if records_exported > 1000:
            # VIOLATION: Just logs, doesn't trigger breach protocol
            logger.error(f"Large export by {user_email}: {records_exported} records")
        return False  # Never triggers breach notification


# =============================================================================
# GDPR — Personal data in source code constants
# =============================================================================

# GDPR VIOLATION: Real-looking personal data of EU residents in source
EU_TEST_DATA = [
    {
        "name": "François Dubois",
        "email": "francois.dubois.private@orange.fr",
        "phone": "+33 6 12 34 56 78",
        "address": "15 Rue de la Paix, 75001 Paris, France",
        "national_id": "1 85 01 75 123 456 78",  # French NIN
        "dob": "1985-01-15",
    },
    {
        "name": "Maria García",
        "email": "maria.garcia.personal@gmail.com",
        "phone": "+34 612 345 678",
        "address": "Calle Gran Vía 28, 28013 Madrid, Spain",
        "dni": "12345678Z",     # Spanish National ID
        "dob": "1990-07-22",
    },
    {
        "name": "Hans Müller",
        "email": "hans.mueller.privat@web.de",
        "phone": "+49 151 12345678",
        "address": "Unter den Linden 5, 10117 Berlin, Germany",
        "tax_id": "DE123456789",
        "dob": "1978-03-10",
    },
]
