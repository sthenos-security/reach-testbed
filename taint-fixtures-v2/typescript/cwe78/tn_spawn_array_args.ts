// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: spawn_array_args_no_shell
// SOURCE: function_parameter
// SINK: child_process.spawn
// TAINT_HOPS: 1
// NOTES: VSCode-style — spawn with array args, no shell interpretation
// REAL_WORLD: microsoft/vscode src/vs/base/node/processes.ts
import { spawn } from 'child_process';

export function installPackage(projectRoot: string, pkg: string): Promise<void> {
    return new Promise((resolve, reject) => {
        // SAFE: spawn with array args — no shell interpretation
        const child = spawn('npm', ['install', '--save', pkg], {
            cwd: projectRoot,
            stdio: 'inherit'
        });
        child.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`npm exited with code ${code}`));
        });
    });
}
