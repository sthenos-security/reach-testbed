"""REACHABLE: AI — called from entrypoint."""

def run_llm_query(user_prompt: str) -> str:
    """LLM01 REACHABLE: unsanitized user input to OpenAI."""
    from openai import OpenAI
    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_prompt}]  # VIOLATION: unsanitized
    )
    return resp.choices[0].message.content
