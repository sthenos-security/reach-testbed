// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: prisma_orm_query
// SOURCE: http_request (req.query)
// SINK: prisma.findMany (ORM)
// TAINT_HOPS: 1
// NOTES: Prisma ORM handles parameterization internally
import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function searchUsers(req: Request, res: Response): Promise<void> {
  const name = req.query.name as string;
  // SAFE: Prisma ORM handles parameterization automatically
  const users = await prisma.user.findMany({
    where: { name: { contains: name } },
  });
  res.json(users);
}
