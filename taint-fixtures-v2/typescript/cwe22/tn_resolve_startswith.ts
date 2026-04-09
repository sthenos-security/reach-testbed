// Fixture: code_patch · CWE-22 Path Traversal · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: path_resolve_startswith_check
// SOURCE: http_request (req.params)
// SINK: fs.readFile (validated path)
// TAINT_HOPS: 1
// NOTES: path.resolve + startsWith validation
import path from 'path';
import { Request, Response } from 'express';

const BASE_DIR = path.resolve('/var/uploads');

export function downloadFile(req: Request, res: Response): void {
  const filename = req.params.filename;
  const filePath = path.resolve(BASE_DIR, filename);
  // SAFE: resolved path validated to stay within base directory
  if (!filePath.startsWith(BASE_DIR)) {
    res.status(403).send('Forbidden');
    return;
  }
  res.sendFile(filePath);
}
