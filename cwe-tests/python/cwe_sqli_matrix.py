# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# CWE-89 (SQL Injection) — Variable Origin Test Matrix
#
# All functions below are REACHABLE (called from Flask routes).
# The test is whether the engine can distinguish:
#   - TRUE POSITIVE:  user-controlled input flows to SQL
#   - FALSE POSITIVE: safe variable (constant, config, cast, ORM) flows to SQL
#   - TRUE NEGATIVE:  parameterized query (should not be flagged at all)
#
# This tests argument propagation and variable origin tracing, not just
# function-level reachability.
# ============================================================================
"""
SQL Injection false positive / true positive matrix.

Every route is REACHABLE. The question is: does the engine correctly
identify which ones have attacker-controlled input flowing into SQL?
"""
from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

DB_PATH = "/tmp/testbed.db"

# App config — not user controlled
APP_CONFIG = {
    "default_user": "system",
    "default_limit": 100,
    "admin_table": "admin_users",
}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================================
# TRUE POSITIVES — user input flows to SQL (MUST be flagged as REACHABLE)
# ============================================================================

# TP-1: request.args → string concat → execute
@app.route('/tp/sqli/concat', methods=['GET'])
def tp_concat():
    """Classic: user input via string concatenation."""
    name = request.args.get('name', '')
    conn = get_db()
    conn.execute("SELECT * FROM users WHERE name = '" + name + "'")
    conn.close()
    return jsonify({'status': 'ok'})


# TP-2: request.args → f-string → execute
@app.route('/tp/sqli/fstring', methods=['GET'])
def tp_fstring():
    """User input via f-string interpolation."""
    user_id = request.args.get('id', '')
    conn = get_db()
    conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    conn.close()
    return jsonify({'status': 'ok'})


# TP-3: request.args → %-format → execute
@app.route('/tp/sqli/percent', methods=['GET'])
def tp_percent():
    """User input via percent formatting."""
    category = request.args.get('cat', '')
    conn = get_db()
    conn.execute("SELECT * FROM products WHERE category = '%s'" % category)
    conn.close()
    return jsonify({'status': 'ok'})


# TP-4: request.args → .format() → execute
@app.route('/tp/sqli/format', methods=['GET'])
def tp_format():
    """User input via .format()."""
    table = request.args.get('table', '')
    conn = get_db()
    conn.execute("SELECT * FROM {}".format(table))
    conn.close()
    return jsonify({'status': 'ok'})


# TP-5: request.json → f-string → execute (POST body)
@app.route('/tp/sqli/json_body', methods=['POST'])
def tp_json_body():
    """User input from POST JSON body."""
    filter_val = request.json.get('filter', '')
    conn = get_db()
    conn.execute(f"DELETE FROM logs WHERE source = '{filter_val}'")
    conn.close()
    return jsonify({'status': 'ok'})


# TP-6: request.args → intermediate variable → execute
@app.route('/tp/sqli/indirect', methods=['GET'])
def tp_indirect():
    """User input assigned to intermediate variable before SQL."""
    raw = request.args.get('q', '')
    search_term = raw.strip()
    query = f"SELECT * FROM items WHERE name LIKE '%{search_term}%'"
    conn = get_db()
    conn.execute(query)
    conn.close()
    return jsonify({'status': 'ok'})


# TP-7: request.args → helper function → execute
@app.route('/tp/sqli/helper', methods=['GET'])
def tp_helper():
    """User input flows through a helper function to SQL."""
    name = request.args.get('name', '')
    results = _unsafe_search(name)
    return jsonify({'results': results})

def _unsafe_search(term):
    """Helper that builds unsafe SQL — argument is user-controlled."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM users WHERE name = '" + term + "'").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================================
# FALSE POSITIVES — safe variable origins (should NOT be flagged, or
# should be downgraded / marked as lower severity)
# ============================================================================

# FP-1: Constant value → f-string → execute
@app.route('/fp/sqli/constant', methods=['GET'])
def fp_constant():
    """Variable is a hardcoded constant — not user-controlled."""
    user_id = 42
    conn = get_db()
    conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    conn.close()
    return jsonify({'status': 'ok'})


# FP-2: Config value → f-string → execute
@app.route('/fp/sqli/config', methods=['GET'])
def fp_config():
    """Variable comes from app config — not user-controlled."""
    table = APP_CONFIG["admin_table"]
    conn = get_db()
    conn.execute(f"SELECT * FROM {table} LIMIT 10")
    conn.close()
    return jsonify({'status': 'ok'})


# FP-3: Env variable → f-string → execute
@app.route('/fp/sqli/env', methods=['GET'])
def fp_env():
    """Variable from environment — server-controlled, not user input."""
    db_schema = os.environ.get("DB_SCHEMA", "public")
    conn = get_db()
    conn.execute(f"SELECT * FROM {db_schema}.users LIMIT 10")
    conn.close()
    return jsonify({'status': 'ok'})


# FP-4: Integer cast → f-string → execute
@app.route('/fp/sqli/int_cast', methods=['GET'])
def fp_int_cast():
    """User input is cast to int — injection not possible."""
    user_id = int(request.args.get('id', '0'))
    conn = get_db()
    conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    conn.close()
    return jsonify({'status': 'ok'})


# FP-5: Computed value → f-string → execute
@app.route('/fp/sqli/computed', methods=['GET'])
def fp_computed():
    """Variable is computed internally — not user input."""
    conn = get_db()
    count = len(conn.execute("SELECT * FROM users").fetchall())
    conn.execute(f"INSERT INTO stats (user_count) VALUES ({count})")
    conn.close()
    return jsonify({'status': 'ok'})


# FP-6: Allowlist-validated input → f-string → execute
@app.route('/fp/sqli/allowlist', methods=['GET'])
def fp_allowlist():
    """User input validated against allowlist — safe."""
    sort_col = request.args.get('sort', 'name')
    allowed = {'name', 'email', 'created_at', 'id'}
    if sort_col not in allowed:
        sort_col = 'name'
    conn = get_db()
    conn.execute(f"SELECT * FROM users ORDER BY {sort_col}")
    conn.close()
    return jsonify({'status': 'ok'})


# FP-7: Loop counter → f-string → execute
@app.route('/fp/sqli/loop', methods=['GET'])
def fp_loop():
    """Variable is a loop counter — not user-controlled."""
    conn = get_db()
    for i in range(5):
        conn.execute(f"SELECT * FROM partitions WHERE partition_id = {i}")
    conn.close()
    return jsonify({'status': 'ok'})


# FP-8: Function return (internal) → f-string → execute
@app.route('/fp/sqli/internal_fn', methods=['GET'])
def fp_internal_fn():
    """Variable comes from an internal function — not user input."""
    table_name = _get_active_table()
    conn = get_db()
    conn.execute(f"SELECT COUNT(*) FROM {table_name}")
    conn.close()
    return jsonify({'status': 'ok'})

def _get_active_table():
    """Returns a hardcoded table name — no user input."""
    return "active_sessions"


# ============================================================================
# TRUE NEGATIVES — parameterized queries (should NOT be flagged at all)
# ============================================================================

# TN-1: Parameterized with ? placeholder
@app.route('/tn/sqli/param_qmark', methods=['GET'])
def tn_param_qmark():
    """Parameterized query with ? — safe by construction."""
    user_id = request.args.get('id', '')
    conn = get_db()
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    conn.close()
    return jsonify({'status': 'ok'})


# TN-2: Parameterized with named placeholder
@app.route('/tn/sqli/param_named', methods=['GET'])
def tn_param_named():
    """Parameterized query with :name — safe by construction."""
    name = request.args.get('name', '')
    conn = get_db()
    conn.execute("SELECT * FROM users WHERE name = :name", {"name": name})
    conn.close()
    return jsonify({'status': 'ok'})


# TN-3: Parameterized with %s (DB-API style)
@app.route('/tn/sqli/param_dbapi', methods=['GET'])
def tn_param_dbapi():
    """Parameterized query with %s tuple — safe by construction."""
    email = request.args.get('email', '')
    conn = get_db()
    conn.execute("SELECT * FROM users WHERE email = %s", (email,))
    conn.close()
    return jsonify({'status': 'ok'})


# TN-4: ORM-style query (no raw SQL)
@app.route('/tn/sqli/orm_style', methods=['GET'])
def tn_orm_style():
    """Simulated ORM query — no raw SQL construction."""
    user_id = request.args.get('id', '')
    # In real code this would be User.query.filter_by(id=user_id)
    # Simulating with parameterized query
    conn = get_db()
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    conn.close()
    return jsonify({'status': 'ok'})


# ============================================================================
# EDGE CASES — tricky patterns that test engine precision
# ============================================================================

# EDGE-1: Mixed safe + unsafe in same function
@app.route('/edge/sqli/mixed', methods=['GET'])
def edge_mixed():
    """One safe variable, one unsafe — in the same function."""
    page_size = 50  # safe — constant
    search = request.args.get('q', '')  # unsafe — user input
    conn = get_db()
    # This line has BOTH: safe page_size, unsafe search
    conn.execute(f"SELECT * FROM items WHERE name = '{search}' LIMIT {page_size}")
    conn.close()
    return jsonify({'status': 'ok'})


# EDGE-2: Conditional — one branch safe, one branch unsafe
@app.route('/edge/sqli/conditional', methods=['GET'])
def edge_conditional():
    """Value depends on a condition — one path is safe, one isn't."""
    mode = request.args.get('mode', 'default')
    if mode == 'admin':
        user_filter = "role = 'admin'"  # safe — constant string
    else:
        user_filter = f"name = '{request.args.get('name', '')}'"  # unsafe
    conn = get_db()
    conn.execute(f"SELECT * FROM users WHERE {user_filter}")
    conn.close()
    return jsonify({'status': 'ok'})


# EDGE-3: Reassignment — variable starts safe, gets overwritten with user input
@app.route('/edge/sqli/reassign', methods=['GET'])
def edge_reassign():
    """Variable starts as constant, then gets overwritten with user input."""
    query_filter = "1=1"  # safe initially
    if request.args.get('name'):
        query_filter = f"name = '{request.args['name']}'"  # unsafe override
    conn = get_db()
    conn.execute(f"SELECT * FROM users WHERE {query_filter}")
    conn.close()
    return jsonify({'status': 'ok'})


# EDGE-4: String join from list containing user input
@app.route('/edge/sqli/join', methods=['GET'])
def edge_join():
    """List of values joined into SQL — one element is user input."""
    ids = request.args.get('ids', '1,2,3')  # user input: "1,2,3" or "1; DROP TABLE--"
    conn = get_db()
    conn.execute(f"SELECT * FROM users WHERE id IN ({ids})")
    conn.close()
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(port=5002)
