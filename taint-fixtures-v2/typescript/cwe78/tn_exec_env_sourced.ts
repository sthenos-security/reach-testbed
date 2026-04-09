// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_env_sourced_command
// SOURCE: environment (process.env)
// SINK: child_process.execSync
// TAINT_HOPS: 1
// NOTES: Environment variables are server-controlled
import { execSync } from 'child_process';

export function runBuild(): string {
  const buildCmd = process.env.BUILD_CMD || 'npm run build';
  // SAFE: command from server environment, not user input
  return execSync(buildCmd).toString();
}
