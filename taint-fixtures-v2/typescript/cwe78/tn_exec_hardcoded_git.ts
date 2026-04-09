// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_hardcoded_command
// SOURCE: none (literal string)
// SINK: child_process.exec
// TAINT_HOPS: 0
// NOTES: VSCode-style — hardcoded git command, cwd from arg but not in command string
// REAL_WORLD: microsoft/vscode src/vs/base/node/processes.ts
import { exec } from 'child_process';

export function getGitStatus(workspaceRoot: string): Promise<string> {
    return new Promise((resolve, reject) => {
        // SAFE: command is hardcoded literal
        exec('git status', { cwd: workspaceRoot }, (error, stdout) => {
            if (error) reject(error);
            else resolve(stdout);
        });
    });
}
