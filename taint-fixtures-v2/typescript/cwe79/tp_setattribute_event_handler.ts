// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: setattribute_user_controlled_attrs
// SOURCE: function_parameter
// SINK: element.setAttribute
// TAINT_HOPS: 1
// NOTES: User-controlled attribute names/values can set onclick, onload etc.
export function createDynamicElement(tagName: string, attrs: Record<string, string>): void {
    const el = document.createElement(tagName);
    for (const [key, value] of Object.entries(attrs)) {
        // VULNERABLE: on* handlers can execute JS
        el.setAttribute(key, value);
    }
    document.body.appendChild(el);
}
