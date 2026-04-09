// Fixture: code_patch · CWE-22 Path Traversal · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: symlink_bypass_normalize
// SOURCE: function_parameter
// SINK: fs.readFileSync
// TAINT_HOPS: 1
// NOTES: path.normalize doesn't resolve symlinks — symlink can escape base
import * as path from 'path';
import * as fs from 'fs';

export function readProtectedFile(baseDir: string, filename: string): string {
    const safePath = path.normalize(path.join(baseDir, filename));
    if (!safePath.startsWith(baseDir)) {
        throw new Error('Path traversal detected');
    }
    // Still vulnerable: symlink can point outside baseDir
    return fs.readFileSync(safePath, 'utf8');
}
