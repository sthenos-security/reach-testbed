// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: spawn_shell_true_user_input
// SOURCE: http_request (req.query)
// SINK: child_process.spawn (shell: true)
// TAINT_HOPS: 1
import { spawn } from 'child_process';
import { Request, Response } from 'express';

export function runWithSpawn(req: Request, res: Response): void {
  const cmd = req.query.cmd as string;
  // VULNERABLE: CWE-78 · spawn with shell:true passes through shell
  const proc = spawn(cmd, { shell: true });
  proc.stdout.on('data', (data) => res.write(data));
  proc.on('close', () => res.end());
}
