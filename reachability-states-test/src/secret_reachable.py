"""
SECRET REACHABLE TEST
=====================
This module IS imported and called from app.py.
Expected: Secrets should be marked as REACHABLE.

Contains hardcoded secrets that ARE used in production code paths.
"""


# Hardcoded API key - REACHABLE (used in get_api_key function called from app.py)
API_KEY = "sk-live-abcdef1234567890abcdef1234567890"

# AWS credentials - REACHABLE
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_api_key() -> str:
    """
    Return the API key.
    This IS called from app.py - secret is REACHABLE.
    """
    return API_KEY


def get_aws_credentials() -> tuple:
    """
    Return AWS credentials.
    Called if app.py uses AWS services.
    """
    return AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def connect_to_database():
    """
    Database connection with hardcoded password - REACHABLE.
    """
    # Hardcoded database password
    db_password = "super_secret_db_password_12345"
    return f"postgresql://admin:{db_password}@localhost:5432/mydb"
