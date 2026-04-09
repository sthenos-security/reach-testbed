// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: spawn_no_shell_user_arg
// SOURCE: http_request (req.query)
// SINK: child_process.spawn (no shell)
// TAINT_HOPS: 1
// NOTES: spawn without shell:true — arguments not shell-interpreted
import { spawn } from 'child_process';
import { Request, Response } from 'express';

export function pingHost(req: Request, res: Response): void {
  const host = req.query.host as string;
  // SAFE: spawn without shell flag — arguments are not shell-interpreted
  const proc = spawn('ping', ['-c', '3', host]);
  proc.stdout.on('data', (data) => res.write(data));
  proc.on('close', () => res.end());
}
