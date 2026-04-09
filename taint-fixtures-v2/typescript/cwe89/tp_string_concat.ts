// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: sql_string_concat_user_input
// SOURCE: http_request (req.body)
// SINK: db.query (string concat)
// TAINT_HOPS: 1
import { Request, Response } from 'express';
import { Pool } from 'pg';

const pool = new Pool();

export async function searchUsers(req: Request, res: Response): Promise<void> {
  const name = req.body.name;
  // VULNERABLE: CWE-89 · string concatenation with user input
  const result = await pool.query("SELECT * FROM users WHERE name LIKE '%" + name + "%'");
  res.json(result.rows);
}
