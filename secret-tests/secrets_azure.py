# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# SECRET: Azure connection strings, SAS tokens, client secrets
# ============================================================================
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── REACHABLE: Azure Storage connection string ───────────────────────────
AZURE_STORAGE_CONNECTION = "DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567ABCDEFGHIJK==;EndpointSuffix=core.windows.net"

# ── REACHABLE: Azure AD client secret ───────────────────────────────────
AZURE_CLIENT_ID = "12345678-1234-1234-1234-123456789abc"
AZURE_TENANT_ID = "87654321-4321-4321-4321-cba987654321"
AZURE_CLIENT_SECRET = "~Abc123Def456Ghi789.Jkl012Mno345Pqr"

# ── REACHABLE: Azure SAS token ──────────────────────────────────────────
BLOB_URL = "https://prodstore.blob.core.windows.net/data?sv=2021-06-08&ss=b&srt=sco&sp=rwdlacitfx&se=2025-12-31&sig=abc123def456%2Fghi789jkl012mno345pqr678stu901%3D"

# ── REACHABLE: Azure SQL connection ─────────────────────────────────────
AZURE_SQL = "Server=tcp:prod-sql.database.windows.net,1433;Database=appdb;User ID=sqladmin;Password=Pr0d_P@ssw0rd!;Encrypt=True;Connection Timeout=30"

@app.route('/api/azure/blobs', methods=['GET'])
def list_blobs():
    return jsonify({'connection': AZURE_STORAGE_CONNECTION[:50] + '...'})

@app.route('/api/azure/auth', methods=['POST'])
def azure_auth():
    return jsonify({'tenant': AZURE_TENANT_ID, 'client': AZURE_CLIENT_ID})

@app.route('/api/azure/query', methods=['GET'])
def azure_query():
    return jsonify({'sql_server': AZURE_SQL.split(';')[0]})

def _dead_azure():
    OLD_KEY = "DefaultEndpointsProtocol=https;AccountName=devstore;AccountKey=DEADBEEF==;EndpointSuffix=core.windows.net"
    return OLD_KEY

if __name__ == '__main__':
    app.run(port=6002)
