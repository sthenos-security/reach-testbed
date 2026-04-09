# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: sql_hardcoded_table_name_parameterized_values
# SOURCE: none (hardcoded constant)
# SINK: cursor.execute (f-string for table, params for values)
# TAINT_HOPS: 0
# NOTES: Dynamic table name from constant — Fleet FP pattern (softwaredb.go)
import sqlite3

TABLES = ["darwin_software", "windows_software", "ubuntu_software"]


def load_software(os_type: str):
    if os_type not in ("darwin", "windows", "ubuntu"):
        raise ValueError("Invalid OS type")
    table = f"{os_type}_software"
    conn = sqlite3.connect("fleet.db")
    cursor = conn.cursor()
    # SAFE: table name from validated constant, WHERE params bound
    cursor.execute(f"SELECT * FROM {table} WHERE active = ?", (True,))
    return cursor.fetchall()
