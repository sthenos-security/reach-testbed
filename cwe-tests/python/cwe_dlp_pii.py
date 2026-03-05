# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Triggers: DLP/PII detection rules
# Tests PII exposure patterns — SSN, credit cards, emails, phone numbers
# ============================================================================
from flask import Flask, request, jsonify
import re
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Hardcoded PII (BAD — should never be in source code)
SAMPLE_CUSTOMERS = [
    {"name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com",
     "phone": "+1-555-123-4567", "dob": "1985-03-15",
     "cc": "4111-1111-1111-1111", "cc_exp": "12/26", "cc_cvv": "123"},
    {"name": "Jane Smith", "ssn": "987-65-4321", "email": "jane@example.com",
     "phone": "+1-555-987-6543", "dob": "1990-07-22",
     "cc": "5500-0000-0000-0004", "cc_exp": "06/27", "cc_cvv": "456"},
    {"name": "Bob Wilson", "ssn": "456-78-9012", "email": "bob@corp.com",
     "phone": "+44-20-7946-0958", "dob": "1978-11-03",
     "cc": "3782-822463-10005", "cc_exp": "03/28", "cc_cvv": "7890"},
]

# REACHABLE: PII in API response (data leak)
@app.route('/api/customers', methods=['GET'])
def list_customers():
    """Returns full PII including SSN and CC — massive data leak."""
    return jsonify({'customers': SAMPLE_CUSTOMERS})

@app.route('/api/customers/<int:idx>', methods=['GET'])
def get_customer(idx):
    """Returns individual customer PII."""
    if 0 <= idx < len(SAMPLE_CUSTOMERS):
        return jsonify(SAMPLE_CUSTOMERS[idx])
    return jsonify({'error': 'not found'}), 404

# REACHABLE: PII in logs (log injection / data leak)
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Logs PII — SSN and CC in plaintext logs."""
    ssn = request.json.get('ssn', '')
    cc = request.json.get('cc_number', '')
    logger.info(f"Login attempt: SSN={ssn}, CC={cc}")  # BAD: PII in logs
    return jsonify({'status': 'ok'})

# REACHABLE: PII processing without sanitization
@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Exports PII as CSV — no masking or encryption."""
    lines = ["name,ssn,email,phone,cc_number"]
    for c in SAMPLE_CUSTOMERS:
        lines.append(f"{c['name']},{c['ssn']},{c['email']},{c['phone']},{c['cc']}")
    return '\n'.join(lines), 200, {'Content-Type': 'text/csv'}

# REACHABLE: PII in error messages
@app.route('/api/verify/identity', methods=['POST'])
def verify_identity():
    """Includes PII in error response."""
    ssn = request.json.get('ssn', '')
    if not re.match(r'^\d{3}-\d{2}-\d{4}$', ssn):
        return jsonify({'error': f'Invalid SSN format: {ssn}'}), 400  # BAD: echoes SSN
    return jsonify({'verified': True})

# Medical records — HIPAA violation pattern
PATIENT_RECORDS = [
    {"patient_id": "P001", "name": "Alice Johnson", "ssn": "111-22-3333",
     "diagnosis": "Type 2 Diabetes", "medications": ["Metformin", "Insulin"],
     "insurance_id": "BCBS-123456789"},
    {"patient_id": "P002", "name": "Charlie Brown", "ssn": "444-55-6666",
     "diagnosis": "Hypertension", "medications": ["Lisinopril"],
     "insurance_id": "AETNA-987654321"},
]

@app.route('/api/patients', methods=['GET'])
def list_patients():
    """Exposes medical records — HIPAA violation."""
    return jsonify({'patients': PATIENT_RECORDS})

# UNREACHABLE: PII in dead code
def _dead_pii_processing():
    dead_ssns = ["000-00-0000", "999-99-9999"]
    dead_cc = "4000-0000-0000-0002"
    return dead_ssns, dead_cc

if __name__ == '__main__':
    app.run(port=5012)
