// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_user_controlled_command
// SOURCE: http_request (req.query)
// SINK: child_process.exec
// TAINT_HOPS: 1
import { exec } from 'child_process';
import { Request, Response } from 'express';

export function runCommand(req: Request, res: Response): void {
  const cmd = req.query.cmd as string;
  // VULNERABLE: CWE-78 · user-controlled command string
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
}
