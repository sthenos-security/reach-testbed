# LLM05 - Improper Output Handling Test Cases
# INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
# Copyright © 2026 Sthenos Security. Test file only.

"""
This file contains intentionally vulnerable code patterns that should
trigger LLM05 (Improper Output Handling) detections.
"""

from openai import OpenAI
import subprocess
import os


# === VULNERABLE: Code execution from LLM output ===

def vulnerable_exec_output(prompt: str) -> str:
    """VULNERABLE: Executing LLM output as code."""
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    code = response.choices[0].message.content
    
    # BAD: Executing LLM output directly
    exec(code)
    return "Executed"


def vulnerable_eval_output(prompt: str) -> any:
    """VULNERABLE: Evaluating LLM output."""
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    expression = response.choices[0].message.content
    
    # BAD: Evaluating LLM output
    result = eval(expression)
    return result


# === VULNERABLE: Shell command from LLM output ===

def vulnerable_shell_execution(prompt: str) -> str:
    """VULNERABLE: Running LLM output as shell command."""
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Generate a shell command"},
            {"role": "user", "content": prompt}
        ]
    )
    
    command = response.choices[0].message.content
    
    # BAD: Executing shell command from LLM
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def vulnerable_os_system(prompt: str) -> int:
    """VULNERABLE: os.system with LLM output."""
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    command = response.choices[0].message.content
    
    # BAD: os.system with untrusted input
    return os.system(command)


# === VULNERABLE: HTML/XSS injection ===

def vulnerable_html_injection(prompt: str) -> str:
    """VULNERABLE: Rendering LLM output as HTML without escaping."""
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    html_content = response.choices[0].message.content
    
    # BAD: Directly embedding in HTML
    return f"<div>{html_content}</div>"


# === VULNERABLE: SQL injection ===

def vulnerable_sql_from_llm(prompt: str, db_connection) -> list:
    """VULNERABLE: Using LLM output in SQL query."""
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Generate a SQL query"},
            {"role": "user", "content": prompt}
        ]
    )
    
    query = response.choices[0].message.content
    
    # BAD: Executing LLM-generated SQL directly
    cursor = db_connection.cursor()
    cursor.execute(query)  # SQL injection risk
    return cursor.fetchall()


# === COMPARISON: SAFE patterns ===

def safe_sandboxed_execution(prompt: str) -> str:
    """SAFE: Sandboxed code execution."""
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    code = response.choices[0].message.content
    
    # GOOD: Use restricted execution environment
    allowed_builtins = {'print': print, 'len': len, 'str': str, 'int': int}
    exec(code, {"__builtins__": allowed_builtins}, {})
    return "Executed in sandbox"


def safe_escaped_html(prompt: str) -> str:
    """SAFE: HTML output properly escaped."""
    from html import escape
    
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    content = response.choices[0].message.content
    
    # GOOD: Escape HTML
    return f"<div>{escape(content)}</div>"
