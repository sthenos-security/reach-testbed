// Fixture: CWE-94 Code Injection - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: new_function_constructor_user_input
// SOURCE: request.body
// SINK: new Function
// TAINT_HOPS: 1
// NOTES: Function constructor with user input - equivalent to eval
import { Request, Response } from 'express';

export function runFormula(req: Request, res: Response) {
    const formula = req.body.formula;
    // VULNERABLE: Function constructor executes arbitrary code
    const fn = new Function('x', 'y', `return ${formula}`);
    res.json({ result: fn(1, 2) });
}
