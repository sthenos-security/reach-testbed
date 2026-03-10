"""NOT_REACHABLE: SECRET — module NEVER imported by entrypoint."""

# All secrets here are NOT_REACHABLE — file never imported
AWS_SECRET_KEY   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # NR
STRIPE_SECRET    = "sk_live_pyNR_xxxxxxxxxxxxxxxxxxxxxxx"         # NR
GITHUB_PAT       = "ghp_pyNRxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"     # NR
TWILIO_TOKEN     = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"           # NR
SENDGRID_KEY     = "SG.pyNR_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"   # NR
PRIVATE_KEY_PEM  = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEANOT_REACHABLE_PYTHON_KEY_TEST_ONLY
-----END RSA PRIVATE KEY-----"""

def get_aws_secret() -> str:
    return AWS_SECRET_KEY

def get_stripe_key() -> str:
    return STRIPE_SECRET
