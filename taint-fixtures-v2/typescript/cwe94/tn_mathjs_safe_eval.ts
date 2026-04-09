// Fixture: CWE-94 Code Injection - TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: mathjs_evaluate_safe
// SOURCE: llm_response
// SINK: math.evaluate
// TAINT_HOPS: 1
// NOTES: Safe alternative - math.js only evaluates math expressions
import * as math from 'mathjs';

export function calculateSafe(expression: string): number {
    // SAFE: math.js sandbox - no access to JS globals, only math operations
    return math.evaluate(expression);
}
