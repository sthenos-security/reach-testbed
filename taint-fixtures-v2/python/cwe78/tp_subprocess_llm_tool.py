# Fixture: CWE-78 Command Injection - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: subprocess_shell_llm_args
# SOURCE: llm_response
# SINK: subprocess.run
# TAINT_HOPS: 1
# NOTES: Agent tool that runs shell commands from LLM output
# REAL_WORLD: langchain-ai/langchain ShellTool pattern
import subprocess

def shell_tool(command: str) -> str:
    # VULNERABLE: LLM-controlled shell command
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
