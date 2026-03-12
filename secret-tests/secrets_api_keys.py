# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# SECRET: Third-party API keys — Stripe, Twilio, SendGrid, GitHub, Slack
# ============================================================================
from flask import Flask, request, jsonify
import requests as http

app = Flask(__name__)

# ── REACHABLE: Stripe keys ──────────────────────────────────────────────
STRIPE_SECRET_KEY = "sk_live_51H7EXAMPLEaBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890"
STRIPE_PUBLISHABLE = "pk_live_51H7EXAMPLEaBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890"

# ── REACHABLE: Twilio ───────────────────────────────────────────────────
TWILIO_ACCOUNT_SID = "AC1234567890abcdef1234567890abcdef"
TWILIO_AUTH_TOKEN = "1234567890abcdef1234567890abcdef"

# ── REACHABLE: SendGrid ────────────────────────────────────────────────
SENDGRID_API_KEY = "SG.aBcDeFgHiJkLmNoPqRsTu.VwXyZ01234567890aBcDeFgHiJkLmNoPqRsTuVwXyZ0"

# ── REACHABLE: GitHub PAT ──────────────────────────────────────────────
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345"

# ── REACHABLE: Slack webhook + bot token ────────────────────────────────
SLACK_WEBHOOK = "https://hooks.slack.com/services/T01234567/B01234567/aBcDeFgHiJkLmNoPqRsTuVw"
SLACK_BOT_TOKEN = "xoxb-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsTuVw"

# ── REACHABLE: OpenAI ──────────────────────────────────────────────────
OPENAI_API_KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890aBcDeFgHiJk"

# ── REACHABLE: Datadog ─────────────────────────────────────────────────
DATADOG_API_KEY = "abcdef1234567890abcdef1234567890ab"
DATADOG_APP_KEY = "abcdef1234567890abcdef1234567890abcdef12"

@app.route('/api/payment/charge', methods=['POST'])
def charge():
    resp = http.post('https://api.stripe.com/v1/charges',
        auth=(STRIPE_SECRET_KEY, ''),
        data={'amount': 1000, 'currency': 'usd'})
    return jsonify(resp.json())

@app.route('/api/sms/send', methods=['POST'])
def send_sms():
    resp = http.post(f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json',
        auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
        data={'To': request.json['to'], 'From': '+15551234567', 'Body': request.json['body']})
    return jsonify(resp.json())

@app.route('/api/email/send', methods=['POST'])
def send_email():
    resp = http.post('https://api.sendgrid.com/v3/mail/send',
        headers={'Authorization': f'Bearer {SENDGRID_API_KEY}'},
        json={'personalizations': [{'to': [{'email': request.json['to']}]}]})
    return jsonify({'status': resp.status_code})

@app.route('/api/notify/slack', methods=['POST'])
def slack_notify():
    http.post(SLACK_WEBHOOK, json={'text': request.json.get('message', 'test')})
    return jsonify({'sent': True})

@app.route('/api/ai/complete', methods=['POST'])
def ai_complete():
    resp = http.post('https://api.openai.com/v1/chat/completions',
        headers={'Authorization': f'Bearer {OPENAI_API_KEY}'},
        json={'model': 'gpt-4', 'messages': [{'role': 'user', 'content': request.json['prompt']}]})
    return jsonify(resp.json())

@app.route('/api/github/repos', methods=['GET'])
def github_repos():
    resp = http.get('https://api.github.com/user/repos',
        headers={'Authorization': f'token {GITHUB_TOKEN}'})
    return jsonify(resp.json())

def _dead_keys():
    OLD_STRIPE = "sk_test_DEADBEEF1234567890"
    OLD_GITHUB = "ghp_DEADBEEF1234567890abcdefghijklmnopqrst"
    return OLD_STRIPE, OLD_GITHUB

if __name__ == '__main__':
    app.run(port=6004)
