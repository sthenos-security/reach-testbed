# Fixture: CWE-94 Code Injection - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: tool_name_allowlist
# SOURCE: llm_response
# SINK: dict_dispatch
# TAINT_HOPS: 1
# NOTES: Tool dispatch with explicit allowlist - LLM can only invoke registered tools

def search(query: str) -> str:
    return f"Results for {query}"

def calculator(expr: str) -> str:
    return str(eval(expr, {"__builtins__": {}}))

TOOLS = {"search": search, "calculator": calculator}

def dispatch_tool(tool_name: str, args: dict):
    if tool_name not in TOOLS:
        raise ValueError(f"Unknown tool: {tool_name}")
    # SAFE: only pre-registered tools can be called
    return TOOLS[tool_name](**args)
