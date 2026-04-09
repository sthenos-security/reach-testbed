# Fixture: CWE-94 Code Injection - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: eval_llm_generated_code
# SOURCE: llm_response
# SINK: eval
# TAINT_HOPS: 1
# NOTES: LangChain-style eval() of LLM-generated expression
# REAL_WORLD: langchain-ai/langchain PythonREPLTool pattern

def calculate(llm_expression: str) -> str:
    # VULNERABLE: LLM can generate arbitrary Python code
    result = eval(llm_expression)
    return str(result)
