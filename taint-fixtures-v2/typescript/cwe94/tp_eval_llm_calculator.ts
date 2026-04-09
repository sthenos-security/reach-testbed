// Fixture: CWE-94 Code Injection - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: eval_llm_expression
// SOURCE: llm_response
// SINK: eval
// TAINT_HOPS: 1
// NOTES: Vercel AI-style eval() of LLM-generated calculator expression
// REAL_WORLD: vercel/ai reasoning-tools.ts
export function calculate(expression: string): number {
    // VULNERABLE: LLM-generated expression can contain arbitrary JS
    return eval(expression);
}
