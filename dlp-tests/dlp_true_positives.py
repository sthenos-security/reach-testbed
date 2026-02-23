"""
DLP/PII True Positives — Python
================================
This file contains REAL PII that SHOULD be detected.
Every item here is expected to increment DLP counters.

Categories: SSN, credit cards, email, phone, address, DOB, 
passport, health data, financial account, biometric data.
"""

# =============================================================================
# SSN — Social Security Numbers (TRUE POSITIVE)
# Format: XXX-XX-XXXX  or  XXXXXXXXX
# =============================================================================

# Plain assignment — SHOULD FLAG
patient_ssn = "123-45-6789"
employee_ssn = "987-65-4321"
ssn_nodash   = "123456789"

# In a dict — SHOULD FLAG
patient_record = {
    "name": "John Smith",
    "ssn": "234-56-7890",
    "dob": "1985-03-15",
}

# In a function return — SHOULD FLAG
def get_patient_ssn(patient_id: int) -> str:
    return "345-67-8901"  # hardcoded SSN in return value


# =============================================================================
# CREDIT CARDS — True Positives
# Luhn-valid numbers (these pass Luhn check)
# =============================================================================

# Visa — SHOULD FLAG
visa_card          = "4532015112830366"
visa_card_spaces   = "4532 0151 1283 0366"
visa_card_dashes   = "4532-0151-1283-0366"

# Mastercard — SHOULD FLAG
mastercard         = "5425233430109903"
mastercard_spaces  = "5425 2334 3010 9903"

# Amex — SHOULD FLAG (15 digits)
amex_card          = "374251018720955"
amex_formatted     = "3742 510187 20955"

# Discover — SHOULD FLAG
discover_card      = "6011111111111117"

# In a payment processing context — SHOULD FLAG
def process_payment(amount: float):
    card_number = "4916338506082832"  # Visa, Luhn-valid
    cvv = "737"
    expiry = "12/26"
    # ... process
    return {"card_last4": card_number[-4:]}


# =============================================================================
# EMAIL ADDRESSES — True Positives (personal/patient/customer context)
# =============================================================================

# Patient/customer emails in healthcare/financial context — SHOULD FLAG
patient_email    = "john.smith@gmail.com"
customer_email   = "jane.doe@yahoo.com"
employee_email   = "bob.wilson@personalmail.com"

patient_data = {
    "patient_id": 12345,
    "email": "mary.johnson@hotmail.com",
    "phone": "+1-555-234-5678",
}

# Email in log/audit context — SHOULD FLAG
audit_log = f"User login: alice.brown@example-personal.com at 2026-01-15 09:23:11"


# =============================================================================
# PHONE NUMBERS — True Positives
# =============================================================================

# US phone numbers — SHOULD FLAG
customer_phone   = "555-234-5678"
patient_phone    = "(415) 555-9876"
phone_intl       = "+1-800-555-0199"
phone_e164       = "+14155559876"

contact_info = {
    "name": "Robert Brown",
    "mobile": "650-555-4321",
    "ssn": "456-78-9012",
}


# =============================================================================
# PHYSICAL ADDRESSES — True Positives
# =============================================================================

# Full home address — SHOULD FLAG
home_address = "123 Main Street, San Francisco, CA 94105"
billing_address = {
    "street": "456 Oak Avenue",
    "city": "Los Angeles",
    "state": "CA",
    "zip": "90210",
    "country": "USA",
}

customer_shipping = {
    "name": "Alice Cooper",
    "address": "789 Pine Road, Seattle, WA 98101",
    "phone": "206-555-1234",
}


# =============================================================================
# DATE OF BIRTH — True Positives
# =============================================================================

patient_dob      = "1985-03-15"
employee_dob     = "March 15, 1985"
dob_record = {
    "name": "Charlie Davis",
    "date_of_birth": "1992-07-22",
    "ssn": "567-89-0123",
}


# =============================================================================
# PASSPORT / GOVERNMENT IDs — True Positives
# =============================================================================

passport_number  = "A12345678"      # US passport format
drivers_license  = "D12345678"      # State DL format
national_id      = "GB-123456789"   # UK NIN pattern


# =============================================================================
# MEDICAL / HEALTH DATA — True Positives (HIPAA-relevant)
# =============================================================================

# Medical record numbers — SHOULD FLAG
mrn = "MRN-2026-001234"

patient_health = {
    "mrn": "MRN-2026-005678",
    "diagnosis": "Type 2 Diabetes",
    "medication": "Metformin 500mg",
    "patient_ssn": "678-90-1234",
    "insurance_id": "BCBS-1234567890",
}

# Drug/prescription data in variables — SHOULD FLAG
prescription = {
    "patient_name": "Dana White",
    "drug": "Oxycodone",
    "dose": "10mg",
    "refills": 2,
    "dea_number": "AB1234563",   # DEA# in prescription
}


# =============================================================================
# FINANCIAL ACCOUNT NUMBERS — True Positives (PCI-relevant)
# =============================================================================

# Bank account — SHOULD FLAG
bank_account     = "123456789012"    # routing: 021000021
routing_number   = "021000021"

wire_transfer = {
    "from_account": "987654321098",
    "to_account":   "123456789012",
    "routing":      "021000021",
    "amount":       10000.00,
}

# IBAN — SHOULD FLAG
iban = "GB29NWBK60161331926819"

# =============================================================================
# COMBINED: Full PII record — maximum severity
# All fields together in one dict — SHOULD FLAG (multiple types)
# =============================================================================
FULL_PII_RECORD = {
    "name":      "Elizabeth Warren",
    "ssn":       "789-01-2345",
    "dob":       "1969-06-22",
    "email":     "liz.warren.personal@gmail.com",
    "phone":     "617-555-8765",
    "address":   "999 Commonwealth Ave, Boston, MA 02215",
    "credit_card": "4916338506082832",
    "card_cvv":    "923",
    "card_expiry": "09/27",
    "bank_acct":   "456789012345",
    "routing":     "021000021",
    "passport":    "P12345678",
    "insurance_id": "UHC-9876543210",
    "mrn":         "MRN-2026-099887",
    "diagnosis":   "Hypertension, Stage 2",
}
