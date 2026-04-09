// Fixture: CWE-78 Command Injection - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: incomplete_shell_quoting_space_only
// SOURCE: function_parameter (args array)
// SINK: child_process.exec via shell
// TAINT_HOPS: 1
// NOTES: Only quotes args containing spaces - metacharacters like $() and backticks pass through
// REAL_WORLD: microsoft/vscode src/vs/workbench/api/node/extHostMcpNode.ts
import { exec } from 'child_process';

function runCommand(binary: string, args: string[]): void {
    // VULNERABLE: only quotes if space present - $(), backticks, ; etc. pass through
    const quoted = args.map(s => s.includes(' ') ? `"${s}"` : s);
    const cmd = [binary, ...quoted].join(' ');
    exec(cmd);
}
