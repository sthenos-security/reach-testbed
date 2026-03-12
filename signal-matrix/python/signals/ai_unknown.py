# Copyright © 2026 Sthenos Security. All rights reserved.
"""UNKNOWN: AI — module imported, safe function called, vulnerable LLM call never reached."""

def get_model_info() -> dict:
    """Safe — returns model metadata only. Called from entrypoint."""
    return {"model": "gpt-4", "provider": "openai", "version": "1.0"}

def run_unchecked_llm_unknown(user_prompt: str) -> str:
    """
    AI UNKNOWN: Direct user input to LLM without sanitization (LLM01 Prompt Injection).
    Module IS imported but this function is NEVER called from any entrypoint.
    Expected: UNKNOWN (import graph hit but no call path).
    """
    from openai import OpenAI
    client = OpenAI()
    # VIOLATION: unsanitized user_prompt directly in messages
    resp = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_prompt}]
    )
    return resp.choices[0].message.content

def execute_llm_output_unknown(llm_response: str) -> None:
    """
    AI UNKNOWN: LLM05 — eval(LLM output). Never called.
    """
    eval(llm_response)  # VIOLATION: executing untrusted LLM output
