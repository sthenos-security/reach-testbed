"""NOT_REACHABLE: DLP — module NEVER imported by entrypoint."""

import sqlite3

SSN_HARDCODED  = "078-05-1120"          # NR: static PII
CARD_HARDCODED = "4532015112830366"     # NR: static credit card

def store_ssn_plaintext(ssn: str) -> None:
    """DLP NOT_REACHABLE: SSN to DB with no encryption. Never called."""
    conn = sqlite3.connect("/tmp/pii_dead.db")
    conn.execute("INSERT INTO users (ssn) VALUES (?)", (ssn,))
    conn.commit()

def send_pii_to_llm_dead(patient: dict) -> str:
    """DLP NOT_REACHABLE: PII → LLM API in dead code."""
    from openai import OpenAI
    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"ssn={patient.get('ssn')} dob={patient.get('dob')}"}]
    )
    return resp.choices[0].message.content

def log_pii_dead(ssn: str, card: str) -> None:
    """DLP NOT_REACHABLE: PII → logger. Never called."""
    import logging
    logging.getLogger(__name__).warning(f"Processing ssn={ssn} card={card}")
