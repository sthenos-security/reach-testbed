// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: execsync_escaped_arg
// SOURCE: function_parameter
// SINK: child_process.execSync
// TAINT_HOPS: 1
// NOTES: VSCode-style — filePath escaped before template literal injection
// REAL_WORLD: microsoft/vscode src/vs/base/node/cp.ts
import { execSync } from 'child_process';

export function getFileChecksum(filePath: string): string {
    const escaped = filePath.replace(/"/g, '\\"');
    const output = execSync(`sha256sum "${escaped}"`, { encoding: 'utf8' });
    return output.trim().split(/\s+/)[0];
}
