// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: execFile_user_as_argument
// SOURCE: http_request (req.query)
// SINK: child_process.execFile
// TAINT_HOPS: 1
// NOTES: execFile does not use shell — user input is a safe argument
import { execFile } from 'child_process';
import { Request, Response } from 'express';

export function lookupHost(req: Request, res: Response): void {
  const host = req.query.host as string;
  // SAFE: execFile does not spawn a shell — arguments passed directly
  execFile('dig', ['+short', host], (err, stdout) => {
    res.send(stdout);
  });
}
