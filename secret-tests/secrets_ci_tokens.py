# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# SECRET: CI/CD tokens — GitHub Actions, GitLab, CircleCI, Jenkins
# ============================================================================
from flask import Flask, jsonify
import requests as http

app = Flask(__name__)

# ── REACHABLE: GitHub App credentials ───────────────────────────────────
GITHUB_APP_ID = "12345"
GITHUB_APP_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2mKqHD0EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz
EXAMPLE1234567890abcdefghijklmnopqrstuvwxyzEXAMPLE1234567890abcdefgh
-----END RSA PRIVATE KEY-----"""
GITHUB_WEBHOOK_SECRET = "whsec_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890"

# ── REACHABLE: GitLab tokens ───────────────────────────────────────────
GITLAB_PERSONAL_TOKEN = "glpat-ABCDEFGHIJKLMNOPQRSTuv"
GITLAB_DEPLOY_TOKEN = "gldt-ABCDEFGHIJKLMNOPQRSTuv"
GITLAB_RUNNER_TOKEN = "GR1348941aBcDeFgHiJkLmNoPqRsTu"
GITLAB_PIPELINE_TOKEN = "glptt-1234567890abcdef1234"

# ── REACHABLE: CircleCI ────────────────────────────────────────────────
CIRCLECI_TOKEN = "cc_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890123456789"

# ── REACHABLE: Jenkins ─────────────────────────────────────────────────
JENKINS_API_TOKEN = "11b1a47b09f3f4c8e1a2b3c4d5e6f7a8b9"
JENKINS_URL = "https://jenkins.internal:8443"

# ── REACHABLE: NPM token ──────────────────────────────────────────────
NPM_TOKEN = "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"

# ── REACHABLE: PyPI token ─────────────────────────────────────────────
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmcCJGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkw"

@app.route('/api/ci/trigger', methods=['POST'])
def trigger_pipeline():
    http.post(f'{JENKINS_URL}/job/deploy/build',
        auth=('admin', JENKINS_API_TOKEN))
    return jsonify({'triggered': True})

@app.route('/api/ci/gitlab', methods=['POST'])
def trigger_gitlab():
    http.post('https://gitlab.com/api/v4/projects/123/trigger/pipeline',
        headers={'PRIVATE-TOKEN': GITLAB_PERSONAL_TOKEN})
    return jsonify({'triggered': True})

@app.route('/api/ci/npm-publish', methods=['POST'])
def npm_publish():
    return jsonify({'token_prefix': NPM_TOKEN[:10]})

def _dead_ci():
    OLD_TOKEN = "glpat-DEADBEEF1234567890ab"
    return OLD_TOKEN

if __name__ == '__main__':
    app.run(port=6006)
