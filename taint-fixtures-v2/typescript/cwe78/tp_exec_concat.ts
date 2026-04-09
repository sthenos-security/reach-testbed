// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_string_concat_user_input
// SOURCE: http_request (req.body)
// SINK: child_process.exec (string concat)
// TAINT_HOPS: 1
import { exec } from 'child_process';
import { Request, Response } from 'express';

export function pingHost(req: Request, res: Response): void {
  const host = req.body.host;
  // VULNERABLE: CWE-78 · string concatenation with user input
  exec("ping -c 3 " + host, (err, stdout) => {
    res.send(stdout);
  });
}
