# Copyright © 2026 Sthenos Security. All rights reserved.
"""NOT_REACHABLE: AI — module NEVER imported by entrypoint."""

def llm_prompt_injection_dead(user_input: str) -> str:
    """LLM01 NOT_REACHABLE: user input to LLM, dead code."""
    from openai import OpenAI
    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return resp.choices[0].message.content

def eval_llm_output_dead(response: str) -> None:
    """LLM05 NOT_REACHABLE: eval(LLM output) in dead code."""
    eval(response)

def exec_with_pii_dead(ssn: str) -> str:
    """AI+DLP NOT_REACHABLE: PII sent to LLM and eval'd. Dead code."""
    from anthropic import Anthropic
    client = Anthropic()
    resp = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=100,
        messages=[{"role": "user", "content": f"Process this SSN: {ssn}"}]
    )
    code = resp.content[0].text
    eval(code)  # double violation: PII in LLM + eval output
    return code
