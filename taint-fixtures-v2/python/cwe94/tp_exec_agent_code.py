# Fixture: CWE-94 Code Injection - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: exec_agent_generated_code
# SOURCE: llm_response
# SINK: exec
# TAINT_HOPS: 1
# NOTES: AutoGen-style exec() of agent-generated Python code
# REAL_WORLD: microsoft/autogen code execution pattern

def execute_agent_action(code: str) -> dict:
    namespace = {}
    # VULNERABLE: agent-controlled code execution
    exec(code, namespace)
    return namespace.get("result", None)
