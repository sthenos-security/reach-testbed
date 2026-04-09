// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: execSync_user_controlled
// SOURCE: http_request (req.params)
// SINK: child_process.execSync
// TAINT_HOPS: 1
import { execSync } from 'child_process';
import { Request, Response } from 'express';

export function getFileInfo(req: Request, res: Response): void {
  const filename = req.params.filename;
  // VULNERABLE: CWE-78 · execSync with user-controlled template literal
  const result = execSync(`file ${filename}`);
  res.send(result.toString());
}
