// Fixture: CWE-94 Code Injection - Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: tool_registry_allowlist_dispatch
// SOURCE: llm_response (tool name)
// SINK: registry.get
// TAINT_HOPS: 1
// NOTES: LangChain4j-style safe tool dispatch - registry acts as allowlist
import java.util.*;

public class TnToolRegistryDispatch {
    interface Tool { Object execute(Map<String, Object> args); }

    private final Map<String, Tool> registry = new HashMap<>();

    public Object executeTool(String toolName, Map<String, Object> args) {
        Tool tool = registry.get(toolName);
        if (tool == null) {
            throw new IllegalArgumentException("Unknown tool: " + toolName);
        }
        // SAFE: only pre-registered tools can be invoked
        return tool.execute(args);
    }
}
