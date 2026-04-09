// Fixture: code_patch · CWE-22 Path Traversal · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: path_join_no_validation
// SOURCE: http_request (req.params)
// SINK: fs.readFile (unvalidated path)
// TAINT_HOPS: 1
import path from 'path';
import fs from 'fs';
import { Request, Response } from 'express';

const BASE_DIR = '/var/uploads';

export function downloadFile(req: Request, res: Response): void {
  const filename = req.params.filename;
  // VULNERABLE: CWE-22 · no validation that path stays within base dir
  const filePath = path.join(BASE_DIR, filename);
  res.sendFile(filePath);
}
