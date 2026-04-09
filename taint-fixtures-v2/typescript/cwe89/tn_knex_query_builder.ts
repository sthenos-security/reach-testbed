// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: knex_query_builder
// SOURCE: http_request (req.query)
// SINK: knex().where (query builder)
// TAINT_HOPS: 1
// NOTES: Knex query builder handles parameterization
import { Request, Response } from 'express';
import knex from 'knex';

const db = knex({ client: 'pg', connection: process.env.DATABASE_URL });

export async function getUser(req: Request, res: Response): Promise<void> {
  const username = req.query.username as string;
  // SAFE: Knex query builder parameterizes values automatically
  const users = await db('users').where('username', username).select('*');
  res.json(users);
}
