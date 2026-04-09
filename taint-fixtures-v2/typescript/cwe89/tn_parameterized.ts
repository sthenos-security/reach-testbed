// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_parameterized_query
// SOURCE: http_request (req.query)
// SINK: db.query (parameterized)
// TAINT_HOPS: 1
// NOTES: Parameterized query with $1 placeholder
import { Request, Response } from 'express';
import { Pool } from 'pg';

const pool = new Pool();

export async function getUser(req: Request, res: Response): Promise<void> {
  const username = req.query.username as string;
  // SAFE: parameterized query with placeholder
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  res.json(result.rows);
}
