# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# SECRET: Cryptocurrency private keys and wallet mnemonics
# ============================================================================
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── REACHABLE: Ethereum private key ─────────────────────────────────────
ETH_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# ── REACHABLE: Bitcoin WIF private key ──────────────────────────────────
BTC_PRIVATE_KEY = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

# ── REACHABLE: Mnemonic seed phrase ─────────────────────────────────────
WALLET_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# ── REACHABLE: Solana private key ───────────────────────────────────────
SOLANA_PRIVATE_KEY = "[174,47,154,16,202,193,206,113,199,190,53,133,169,175,31,56,222,53,138,189,224,216,117,173,10,149,53,45,73,251,237,246,15,236,199,108,207,149,53,145,73,251,237,246,15,236,199,108]"

@app.route('/api/wallet/sign', methods=['POST'])
def sign_transaction():
    tx_data = request.json.get('tx', {})
    return jsonify({'signed': True, 'key_prefix': ETH_PRIVATE_KEY[:10]})

@app.route('/api/wallet/balance', methods=['GET'])
def get_balance():
    return jsonify({'eth': '1.5', 'btc': '0.05'})

def _dead_wallet():
    OLD_KEY = "0xDEADBEEF1234567890abcdef1234567890abcdef1234567890abcdef12345678"
    return OLD_KEY

if __name__ == '__main__':
    app.run(port=6007)
