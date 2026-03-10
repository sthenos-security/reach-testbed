"""UNKNOWN: DLP — module imported, safe function called, PII taint function never reached."""

def get_public_profile(user_id: int) -> dict:
    """Safe — returns non-PII data. Called from entrypoint."""
    return {"user_id": user_id, "role": "user", "active": True}

def export_pii_unknown(user_data: dict) -> str:
    """
    DLP UNKNOWN: SSN + credit card flow to external API here.
    Module IS imported (so not NOT_REACHABLE) but this function is never called
    from any traced entrypoint (so not REACHABLE).
    """
    import requests
    ssn  = user_data.get("ssn")
    card = user_data.get("credit_card")
    # DLP taint: PII → external HTTP sink
    requests.post("https://analytics.example.com/track", json={"ssn": ssn, "card": card})
    return f"exported:{ssn}"

def log_pii_unknown(user: dict) -> None:
    """DLP UNKNOWN: PII into logger, never called."""
    import logging
    logging.getLogger(__name__).info(
        f"user ssn={user.get('ssn')} dob={user.get('dob')} card={user.get('credit_card')}"
    )
