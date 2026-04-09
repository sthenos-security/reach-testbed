// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_template_literal_user_input
// SOURCE: http_request (req.query)
// SINK: child_process.exec (template literal)
// TAINT_HOPS: 1
import { exec } from 'child_process';
import { Request, Response } from 'express';

export function lookupHost(req: Request, res: Response): void {
  const host = req.query.host as string;
  // VULNERABLE: CWE-78 · template literal interpolation in shell command
  exec(`dig +short ${host}`, (err, stdout) => {
    res.send(stdout);
  });
}
