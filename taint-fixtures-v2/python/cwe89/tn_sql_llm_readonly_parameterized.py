# Fixture: CWE-89 SQL Injection - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: sql_llm_readonly_with_validation
# SOURCE: llm_response (validated)
# SINK: cursor.execute
# TAINT_HOPS: 1
# NOTES: Text-to-SQL with read-only validation + parameterized WHERE
import sqlite3, re

ALLOWED_TABLES = {"users", "orders", "products"}

def safe_text_to_sql(table: str, where_col: str, where_val: str) -> list:
    if table not in ALLOWED_TABLES:
        raise ValueError(f"Table not allowed: {table}")
    if not re.match(r'^[a-zA-Z_]+$', where_col):
        raise ValueError(f"Invalid column: {where_col}")
    conn = sqlite3.connect("app.db")
    # SAFE: table allowlisted, column validated, value parameterized
    return conn.execute(f"SELECT * FROM {table} WHERE {where_col} = ?", (where_val,)).fetchall()
