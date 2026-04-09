// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: sql_template_literal_user_input
// SOURCE: http_request (req.query)
// SINK: db.query (template literal)
// TAINT_HOPS: 1
import { Request, Response } from 'express';
import { Pool } from 'pg';

const pool = new Pool();

export async function getUser(req: Request, res: Response): Promise<void> {
  const username = req.query.username as string;
  // VULNERABLE: CWE-89 · template literal interpolation in SQL
  const result = await pool.query(`SELECT * FROM users WHERE username = '${username}'`);
  res.json(result.rows);
}
