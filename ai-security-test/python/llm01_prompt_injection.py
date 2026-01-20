# LLM01 - Prompt Injection Test Cases
# INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
# Copyright © 2026 Sthenos Security. Test file only.

"""
This file contains intentionally vulnerable code patterns that should
trigger LLM01 (Prompt Injection) detections.
"""

from openai import OpenAI
from anthropic import Anthropic
from langchain.llms import OpenAI as LangChainOpenAI
from langchain.prompts import PromptTemplate


# === VULNERABLE: Direct user input in prompt ===

def vulnerable_chat_direct_input(user_message: str) -> str:
    """VULNERABLE: User input directly in prompt without sanitization."""
    client = OpenAI()
    
    # BAD: User input directly concatenated into prompt
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_message}  # Direct user input
        ]
    )
    return response.choices[0].message.content


def vulnerable_f_string_injection(user_query: str) -> str:
    """VULNERABLE: F-string prompt injection."""
    client = Anthropic()
    
    # BAD: User input in f-string template
    prompt = f"Answer this question: {user_query}"
    
    message = client.messages.create(
        model="claude-3-sonnet-20240229",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text


def vulnerable_format_injection(template: str, user_data: dict) -> str:
    """VULNERABLE: .format() with user-controlled data."""
    client = OpenAI()
    
    # BAD: User data in .format() 
    prompt = "Process this request: {request}".format(**user_data)
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


# === VULNERABLE: System prompt manipulation ===

def vulnerable_system_prompt_override(user_instructions: str) -> str:
    """VULNERABLE: User can override system prompt."""
    client = OpenAI()
    
    # BAD: User input as system message
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": user_instructions},  # User controls system!
            {"role": "user", "content": "Hello"}
        ]
    )
    return response.choices[0].message.content


# === VULNERABLE: LangChain template injection ===

def vulnerable_langchain_template(user_template: str) -> str:
    """VULNERABLE: User-controlled LangChain template."""
    llm = LangChainOpenAI()
    
    # BAD: User controls the template
    template = PromptTemplate.from_template(user_template)
    chain = template | llm
    
    return chain.invoke({})


def vulnerable_langchain_variables(user_vars: dict) -> str:
    """VULNERABLE: User-controlled template variables without validation."""
    llm = LangChainOpenAI()
    
    template = PromptTemplate(
        template="You are a {role}. Answer: {question}",
        input_variables=["role", "question"]
    )
    
    # BAD: User controls variables without sanitization
    chain = template | llm
    return chain.invoke(user_vars)


# === COMPARISON: SAFE patterns (should NOT trigger) ===

def safe_sanitized_input(user_message: str) -> str:
    """SAFE: Input sanitized before use."""
    from html import escape
    
    client = OpenAI()
    
    # GOOD: Sanitize user input
    sanitized = escape(user_message)
    if len(sanitized) > 1000:
        sanitized = sanitized[:1000]
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": sanitized}
        ]
    )
    return response.choices[0].message.content


def safe_hardcoded_prompt() -> str:
    """SAFE: Hardcoded prompt, no user input."""
    client = OpenAI()
    
    # GOOD: No user input in prompt
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is 2+2?"}
        ]
    )
    return response.choices[0].message.content
