# GRC Tests — README
# ===================
# This directory contains compliance violation test cases for GRC standards.
#
# Files:
#   pci_dss_violations.py  — PCI-DSS Req 3,4,6,8,10 violations
#   hipaa_violations.py    — HIPAA §164.312 Security Rule violations
#   gdpr_violations.py     — GDPR Art. 5,17,25,32,33 violations
#   sox_ccpa_nist_fedramp.py — SOX §302/404/802, CCPA §1798, NIST SP 800-53, FedRAMP
#
# Purpose:
#   Each file intentionally contains code patterns that violate specific
#   regulatory requirements. REACHABLE should detect:
#     - CWE findings (weak crypto, SQL injection, etc.)
#     - DLP/PII findings (PHI, PAN, SSN, etc.)
#     - Secret findings (hardcoded credentials, API keys)
#     - Config findings (insecure defaults)
#
# Expected signal coverage:
#   CVE:    0 (no dependency vulnerabilities in these files)
#   CWE:    15+ (injection, weak crypto, SSRF, hardcoded creds)
#   DLP:    40+ (PHI, PAN, SSN, addresses, emails across all files)
#   Secret: 20+ (API keys, DB passwords, encryption keys)
#   Config:  5+ (insecure defaults, bypass tokens)
