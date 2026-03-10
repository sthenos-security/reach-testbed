"""REACHABLE: SECRET — called from entrypoint."""
PAYMENT_TOKEN = "sk_live_pyREACH_xxxxxxxxxxxxxxxxxxx"  # REACHABLE secret

def get_payment_token() -> str:
    return PAYMENT_TOKEN
