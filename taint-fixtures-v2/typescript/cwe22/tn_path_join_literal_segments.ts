// Fixture: code_patch · CWE-22 Path Traversal · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: path_join_literal_suffix
// SOURCE: none (literal segments)
// SINK: path.join
// TAINT_HOPS: 0
// NOTES: VSCode-style — path.join with hardcoded segments like 'package.json'
// REAL_WORLD: microsoft/vscode src/vs/code/node/paths.ts
import * as path from 'path';
import * as os from 'os';

export function getExtensionManifest(extensionId: string): string {
    const basePath = process.env.VSCODE_EXTENSIONS ||
        path.join(os.homedir(), '.vscode', 'extensions');
    return path.join(basePath, extensionId, 'package.json');
}
