// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: typeorm_raw_query_concat
// SOURCE: http_request (req.query)
// SINK: repository.query (string concat)
// TAINT_HOPS: 1
import { Request, Response } from 'express';
import { getRepository } from 'typeorm';
import { User } from '../entities/User';

export async function findUser(req: Request, res: Response): Promise<void> {
  const name = req.query.name as string;
  const repo = getRepository(User);
  // VULNERABLE: CWE-89 · TypeORM raw query with string concatenation
  const users = await repo.query("SELECT * FROM users WHERE name = '" + name + "'");
  res.json(users);
}
