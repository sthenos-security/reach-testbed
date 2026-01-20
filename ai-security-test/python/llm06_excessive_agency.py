# LLM06 - Excessive Agency Test Cases
# INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
# Copyright © 2026 Sthenos Security. Test file only.

"""
This file contains intentionally vulnerable code patterns that should
trigger LLM06 (Excessive Agency) detections.
"""

from openai import OpenAI
from langchain.agents import initialize_agent, AgentType
from langchain.tools import Tool, ShellTool, PythonREPLTool
from langchain.llms import OpenAI as LangChainOpenAI
import subprocess


# === VULNERABLE: Dangerous tool access ===

def vulnerable_shell_tool():
    """VULNERABLE: LLM agent with unrestricted shell access."""
    llm = LangChainOpenAI()
    
    # BAD: Shell tool with no restrictions
    shell_tool = ShellTool()
    
    tools = [shell_tool]
    
    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )
    
    return agent


def vulnerable_python_repl():
    """VULNERABLE: LLM agent with unrestricted Python REPL."""
    llm = LangChainOpenAI()
    
    # BAD: Python REPL with no sandboxing
    python_tool = PythonREPLTool()
    
    tools = [python_tool]
    
    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )
    
    return agent


# === VULNERABLE: File system access ===

def vulnerable_file_write_tool():
    """VULNERABLE: LLM can write arbitrary files."""
    llm = LangChainOpenAI()
    
    def write_file(path_and_content: str) -> str:
        path, content = path_and_content.split("|||")
        # BAD: No path validation, can write anywhere
        with open(path, 'w') as f:
            f.write(content)
        return f"Written to {path}"
    
    file_tool = Tool(
        name="write_file",
        func=write_file,
        description="Write content to a file. Format: path|||content"
    )
    
    tools = [file_tool]
    
    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
    )
    
    return agent


def vulnerable_file_delete_tool():
    """VULNERABLE: LLM can delete arbitrary files."""
    import os
    llm = LangChainOpenAI()
    
    def delete_file(path: str) -> str:
        # BAD: No validation, can delete anything
        os.remove(path)
        return f"Deleted {path}"
    
    delete_tool = Tool(
        name="delete_file",
        func=delete_file,
        description="Delete a file at the given path"
    )
    
    tools = [delete_tool]
    
    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
    )
    
    return agent


# === VULNERABLE: Network access ===

def vulnerable_http_request_tool():
    """VULNERABLE: LLM can make arbitrary HTTP requests (SSRF risk)."""
    import requests
    llm = LangChainOpenAI()
    
    def make_request(url: str) -> str:
        # BAD: No URL validation, SSRF risk
        response = requests.get(url)
        return response.text[:1000]
    
    http_tool = Tool(
        name="http_request",
        func=make_request,
        description="Make HTTP GET request to any URL"
    )
    
    tools = [http_tool]
    
    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
    )
    
    return agent


# === VULNERABLE: Database operations ===

def vulnerable_database_tool(db_connection):
    """VULNERABLE: LLM can execute arbitrary SQL."""
    llm = LangChainOpenAI()
    
    def execute_sql(query: str) -> str:
        # BAD: No query validation, can DROP tables etc
        cursor = db_connection.cursor()
        cursor.execute(query)
        return str(cursor.fetchall())
    
    sql_tool = Tool(
        name="execute_sql",
        func=execute_sql,
        description="Execute any SQL query on the database"
    )
    
    tools = [sql_tool]
    
    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
    )
    
    return agent


# === VULNERABLE: No human approval for dangerous actions ===

def vulnerable_auto_execute():
    """VULNERABLE: Automatic execution without human approval."""
    llm = LangChainOpenAI()
    
    def dangerous_action(action: str) -> str:
        # BAD: No human-in-the-loop
        subprocess.run(action, shell=True)
        return "Executed"
    
    action_tool = Tool(
        name="execute_action",
        func=dangerous_action,
        description="Execute a system action"
    )
    
    # BAD: Agent runs autonomously
    agent = initialize_agent(
        [action_tool],
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        max_iterations=10,  # Multiple autonomous steps
        handle_parsing_errors=True
    )
    
    return agent


# === COMPARISON: SAFE patterns ===

def safe_restricted_tool():
    """SAFE: Tool with proper restrictions."""
    llm = LangChainOpenAI()
    
    ALLOWED_COMMANDS = {'ls', 'pwd', 'whoami'}
    
    def restricted_shell(command: str) -> str:
        # GOOD: Whitelist validation
        if command.split()[0] not in ALLOWED_COMMANDS:
            return "Command not allowed"
        return subprocess.check_output(command.split(), text=True)
    
    restricted_tool = Tool(
        name="restricted_shell",
        func=restricted_shell,
        description="Execute only whitelisted commands: ls, pwd, whoami"
    )
    
    agent = initialize_agent(
        [restricted_tool],
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        max_iterations=3  # Limited iterations
    )
    
    return agent


def safe_human_approval_required():
    """SAFE: Human approval for dangerous actions."""
    llm = LangChainOpenAI()
    
    def action_with_approval(action: str) -> str:
        # GOOD: Require human approval
        print(f"Proposed action: {action}")
        approval = input("Approve? (yes/no): ")
        if approval.lower() != 'yes':
            return "Action rejected by human"
        return "Action approved and executed"
    
    tool = Tool(
        name="approved_action",
        func=action_with_approval,
        description="Action requiring human approval"
    )
    
    return initialize_agent([tool], llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
