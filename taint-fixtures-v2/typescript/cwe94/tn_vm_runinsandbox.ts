// Fixture: CWE-94 Code Injection - TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: vm2_sandbox_execution
// SOURCE: request.body
// SINK: vm.runInNewContext (sandboxed)
// TAINT_HOPS: 1
// NOTES: Node.js vm module with restricted sandbox context
import * as vm from 'vm';

const SAFE_CONTEXT = { Math, parseInt, parseFloat, console: { log: () => {} } };

export function evalExpression(code: string): any {
    const sandbox = Object.create(null);
    Object.assign(sandbox, SAFE_CONTEXT);
    // SAFE: restricted sandbox context, no access to require/process/global
    return vm.runInNewContext(code, sandbox, { timeout: 1000 });
}
