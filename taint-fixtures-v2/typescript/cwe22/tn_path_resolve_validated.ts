// Fixture: code_patch · CWE-22 Path Traversal · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: path_resolve_startswith_check
// SOURCE: function_parameter
// SINK: path.resolve
// TAINT_HOPS: 1
// NOTES: VSCode-style — resolved path validated against workspace root
// REAL_WORLD: microsoft/vscode src/vs/platform/files/common/fileService.ts
import * as path from 'path';

export function resolvePath(workspaceRoot: string, userPath: string): string {
    const resolved = path.resolve(workspaceRoot, userPath);
    const normalized = path.normalize(resolved);
    if (!normalized.startsWith(workspaceRoot)) {
        throw new Error('Path traversal detected');
    }
    return normalized;
}
