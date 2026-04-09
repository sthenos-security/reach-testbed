# Fixture: CWE-89 SQL Injection - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: sql_from_llm_text2sql
# SOURCE: llm_response
# SINK: cursor.execute
# TAINT_HOPS: 1
# NOTES: Text-to-SQL pattern - LLM generates SQL query, executed directly
# REAL_WORLD: langchain-ai/langchain SQLDatabaseChain
import sqlite3

def text_to_sql_query(llm_sql: str) -> list:
    conn = sqlite3.connect("app.db")
    # VULNERABLE: LLM-generated SQL executed directly
    return conn.execute(llm_sql).fetchall()
