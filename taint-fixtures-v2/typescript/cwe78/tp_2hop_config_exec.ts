// Fixture: CWE-78 Command Injection - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: multi_hop_object_property_to_exec
// SOURCE: request.body
// SINK: child_process.exec
// TAINT_HOPS: 2
// NOTES: Taint flows through object destructuring to shell command
import { exec } from 'child_process';
import { Request, Response } from 'express';

export function runBuild(req: Request, res: Response) {
    const { repo, branch } = req.body;
    const cloneCmd = `git clone ${repo} && cd ${repo.split('/').pop()} && git checkout ${branch}`;
    // VULNERABLE: 2-hop through destructuring
    exec(cloneCmd, (err, stdout) => {
        res.json({ output: stdout });
    });
}
