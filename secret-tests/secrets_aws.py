# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# SECRET: AWS Access Keys, Session Tokens — multiple embedding patterns
# ============================================================================
from flask import Flask, jsonify
import boto3

app = Flask(__name__)

# ── REACHABLE: Hardcoded AWS credentials ─────────────────────────────────
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

AWS_CONFIG = {
    "aws_access_key_id": "AKIAI44QH8DHBEXAMPLE",
    "aws_secret_access_key": "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    "aws_session_token": "FwoGZXIvYXdzEBYaDHqa0AP1rsCRz5EXAMPLE",
    "region": "us-east-1",
}

@app.route('/api/s3/list', methods=['GET'])
def list_buckets():
    client = boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    return jsonify({'buckets': []})

@app.route('/api/s3/upload', methods=['POST'])
def upload():
    client = boto3.client('s3', **{k: v for k, v in AWS_CONFIG.items() if k != 'region'})
    return jsonify({'status': 'uploaded'})

def _dead_aws():
    return boto3.client('s3', aws_access_key_id="AKIAIOSFODNN7DEADBEEF",
                        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEADBEEFKEY")

if __name__ == '__main__':
    app.run(port=6001)
