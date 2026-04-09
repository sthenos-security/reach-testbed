// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_sanitized_shell_metachar
// SOURCE: function_parameter
// SINK: child_process.exec
// TAINT_HOPS: 1
// NOTES: VSCode-style — input sanitized by regex escaping shell metacharacters
// REAL_WORLD: microsoft/vscode src/vs/workbench/contrib/git/common/git.ts
import { exec } from 'child_process';

export function gitCommit(message: string): Promise<void> {
    const safeMessage = message
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/`/g, '\\`')
        .replace(/\$/g, '\\$');
    return new Promise((resolve, reject) => {
        exec(`git commit -m "${safeMessage}"`, {}, (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}
