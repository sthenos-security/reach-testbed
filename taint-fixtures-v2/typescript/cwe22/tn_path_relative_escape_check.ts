// Fixture: code_patch · CWE-22 Path Traversal · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: path_relative_dotdot_check
// SOURCE: function_parameter
// SINK: path.relative
// TAINT_HOPS: 1
// NOTES: Uses path.relative() to detect directory escape
import * as path from 'path';

export function getRelativePath(basePath: string, target: string): string {
    const resolved = path.resolve(target);
    const relative = path.relative(basePath, resolved);
    if (relative.startsWith('..')) {
        throw new Error('Target outside base directory');
    }
    return relative;
}
