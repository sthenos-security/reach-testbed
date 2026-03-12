# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# SECRET: Database connection strings with embedded passwords
# ============================================================================
from flask import Flask, jsonify

app = Flask(__name__)

# ── REACHABLE: PostgreSQL connection strings ─────────────────────────────
POSTGRES_URL = "postgresql://appuser:S3cur3_Pr0d_P@ss!@db-primary.internal:5432/production"
POSTGRES_REPLICA = "postgresql://readonly:R3pl1ca_P@ss@db-replica.internal:5432/production"

# ── REACHABLE: MySQL connection ─────────────────────────────────────────
MYSQL_URL = "mysql://root:MyS0L_r00t_2024!@mysql.internal:3306/webapp"

# ── REACHABLE: MongoDB connection ───────────────────────────────────────
MONGO_URI = "mongodb://admin:M0ng0_Adm1n_K3y@mongo-cluster.internal:27017/app?authSource=admin&replicaSet=rs0"

# ── REACHABLE: Redis with password ──────────────────────────────────────
REDIS_URL = "redis://:R3d1s_C@che_P@ss@redis.internal:6379/0"

# ── REACHABLE: Elasticsearch ────────────────────────────────────────────
ELASTIC_URL = "https://elastic:El@st1c_S3arch_K3y@es-cluster.internal:9200"

# ── REACHABLE: Connection string in dict ────────────────────────────────
DB_CONFIG = {
    "host": "db-primary.internal",
    "port": 5432,
    "user": "appuser",
    "password": "S3cur3_Pr0d_P@ss!",
    "database": "production",
    "sslmode": "require",
}

@app.route('/api/db/status', methods=['GET'])
def db_status():
    return jsonify({'postgres': POSTGRES_URL.split('@')[1], 'mongo': 'connected'})

@app.route('/api/db/config', methods=['GET'])
def db_config():
    return jsonify({'host': DB_CONFIG['host'], 'port': DB_CONFIG['port']})

@app.route('/api/cache/ping', methods=['GET'])
def cache_ping():
    return jsonify({'redis': REDIS_URL.split('@')[1]})

def _dead_db():
    OLD_DB = "postgresql://old_user:0ld_p@ss@decommissioned-db:5432/legacy"
    return OLD_DB

if __name__ == '__main__':
    app.run(port=6003)
