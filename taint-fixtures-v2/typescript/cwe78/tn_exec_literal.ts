// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_fully_literal
// SOURCE: none (literal string)
// SINK: child_process.exec
// TAINT_HOPS: 0
// NOTES: Fully literal command — no user input
import { exec } from 'child_process';

export function checkDiskSpace(): Promise<string> {
  return new Promise((resolve, reject) => {
    // SAFE: fully literal command string
    exec('df -h', (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}
