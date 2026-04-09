// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_fully_static_query
// SOURCE: none
// SINK: db.query
// TAINT_HOPS: 0
// NOTES: Fully static SQL — no variables
import { Pool } from 'pg';

const pool = new Pool();

export async function countActiveUsers(): Promise<number> {
  // SAFE: fully static SQL query
  const result = await pool.query('SELECT COUNT(*) FROM users WHERE active = true');
  return parseInt(result.rows[0].count, 10);
}
