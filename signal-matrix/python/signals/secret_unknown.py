"""UNKNOWN: SECRET — module imported, public config returned, internal secret never accessed."""

# Public — fine to expose
PUBLIC_APP_NAME = "signal-matrix-test"
PUBLIC_VERSION  = "1.0.0"

# Internal secret — in imported module but the function that uses it is never called
_INTERNAL_API_KEY = "sk_live_pyUnknown_xxxxxxxxxxxxxxxxxxx"  # UNKNOWN secret
_DB_PASSWORD      = "db_pass_unknown_99999"                  # UNKNOWN secret

def get_public_config() -> dict:
    """Safe function — called from entrypoint. No secret exposure here."""
    return {"app": PUBLIC_APP_NAME, "version": PUBLIC_VERSION}

def get_internal_secret_unknown() -> str:
    """
    SECRET UNKNOWN: returns _INTERNAL_API_KEY but is NEVER called from entrypoint.
    Module is imported → UNKNOWN (not NOT_REACHABLE).
    Function not on call path → not REACHABLE.
    """
    return _INTERNAL_API_KEY

def connect_db_unknown() -> str:
    """SECRET UNKNOWN: uses _DB_PASSWORD, never called."""
    return f"postgresql://user:{_DB_PASSWORD}@localhost/prod"
