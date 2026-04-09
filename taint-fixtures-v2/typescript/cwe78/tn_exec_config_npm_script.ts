// Fixture: code_patch · CWE-78 Command Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_config_sourced_script
// SOURCE: config_file (package.json)
// SINK: child_process.exec
// TAINT_HOPS: 1
// NOTES: VSCode-style — npm script name from package.json, not direct user input
// REAL_WORLD: microsoft/vscode src/vs/workbench/contrib/npm/npmScriptRunner.ts
import { exec } from 'child_process';

export function runNpmScript(scriptName: string, projectRoot: string): Promise<string> {
    // scriptName comes from package.json 'scripts' field (read-only config)
    return new Promise((resolve, reject) => {
        exec(`npm run ${scriptName}`, { cwd: projectRoot }, (error, stdout) => {
            if (error) reject(error);
            else resolve(stdout);
        });
    });
}
