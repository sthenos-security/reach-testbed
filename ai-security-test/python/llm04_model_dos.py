"""
OWASP LLM Top 10 — LLM04: Model Denial of Service
====================================================
Intentionally vulnerable patterns for scanner validation.
Copyright © 2026 Sthenos Security. Test file only.
"""

# LLM04: Model Denial of Service
# Attackers send resource-exhausting inputs to overload LLM inference,
# causing degraded performance or cost amplification.

# === VULNERABLE: No token/length limits on user input ===

def chat_no_limits(user_input: str) -> str:
    """VULNERABLE: No max_tokens cap, no input length limit."""
    from openai import OpenAI
    client = OpenAI()
    # LLM04: max_tokens not set — attacker can force very long completions
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}],
        # max_tokens missing — defaults to model max (8192/128k)
    )
    return response.choices[0].message.content

def summarize_document(document: str) -> str:
    """VULNERABLE: Arbitrarily large document passed to LLM."""
    from anthropic import Anthropic
    client = Anthropic()
    # LLM04: No document size check — attacker sends 1M token document
    message = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=4096,
        messages=[{"role": "user", "content": f"Summarize: {document}"}],
        # No input length check
    )
    return message.content[0].text

def recursive_chain_unlimited(task: str, depth: int) -> str:
    """VULNERABLE: Recursive LLM calls with no depth limit."""
    from openai import OpenAI
    client = OpenAI()
    # LLM04: No recursion depth limit — exponential cost amplification
    if depth > 0:
        subtask_response = recursive_chain_unlimited(f"subtask of: {task}", depth - 1)
        prompt = f"Given: {subtask_response}\nNow do: {task}"
    else:
        prompt = task
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content

def batch_process_no_rate_limit(items: list) -> list:
    """VULNERABLE: Batch LLM calls with no rate limiting or budget cap."""
    from openai import OpenAI
    client = OpenAI()
    results = []
    # LLM04: No per-user rate limit, no cost circuit breaker
    for item in items:  # attacker passes 10,000 items
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": str(item)}],
        )
        results.append(response.choices[0].message.content)
    return results

def generate_embeddings_unchecked(texts: list) -> list:
    """VULNERABLE: Embedding API called with no size or count limits."""
    from openai import OpenAI
    client = OpenAI()
    # LLM04: No limit on number of texts or text length
    response = client.embeddings.create(
        model="text-embedding-ada-002",
        input=texts,  # can be thousands of large texts
    )
    return [e.embedding for e in response.data]


# === SAFE patterns ===

MAX_INPUT_TOKENS = 4000
MAX_OUTPUT_TOKENS = 1000

def chat_with_limits(user_input: str) -> str:
    """SAFE: Input truncated, output capped."""
    from openai import OpenAI
    client = OpenAI()
    # Truncate input to safe length
    truncated = user_input[:MAX_INPUT_TOKENS * 4]  # rough char-to-token ratio
    response = client.chat.completions.create(
        model="gpt-4",
        max_tokens=MAX_OUTPUT_TOKENS,
        messages=[{"role": "user", "content": truncated}],
    )
    return response.choices[0].message.content
