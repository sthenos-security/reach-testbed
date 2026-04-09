# Fixture: CWE-94 Code Injection - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: dynamic_dispatch_llm_tool_name
# SOURCE: llm_response
# SINK: getattr
# TAINT_HOPS: 1
# NOTES: Agent framework pattern - LLM chooses function name, getattr dispatches
# REAL_WORLD: langchain-ai/langchain agent tool dispatch
import importlib

def call_tool(tool_name: str, args: dict):
    module = importlib.import_module("tools")
    # VULNERABLE: LLM controls function selection
    fn = getattr(module, tool_name)
    return fn(**args)
