// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: execSync_literal_command
// SOURCE: none (literal string)
// SINK: child_process.execSync
// TAINT_HOPS: 0
// NOTES: Fully literal command — common in build scripts
import { execSync } from 'child_process';

export function installDeps(): string {
  // SAFE: fully literal build command
  return execSync('npm install').toString();
}
