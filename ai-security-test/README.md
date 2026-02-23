# AI Security Test Cases for REACHABLE
# Copyright © 2026 Sthenos Security. All rights reserved.

This directory contains intentionally vulnerable AI/LLM/Agentic code for testing
REACHABLE's AI security scanner.

Three OWASP frameworks are covered:
- **OWASP LLM Top 10:2025** — LLM application security (LLM01–LLM10)
- **OWASP Top 10 for Agentic Applications:2026** — Autonomous AI agent security (ASI01–ASI10)
- **OWASP Top 10:2025** — Web application security (A01–A10, referenced in CWE tests)

---

## OWASP LLM Top 10:2025 Coverage

| Category | Description | Test Files |
|----------|-------------|------------|
| **LLM01** | Prompt Injection | `python/llm01_prompt_injection.py`, `typescript/ai_vulnerabilities.ts` |
| **LLM02** | Sensitive Information Disclosure | `python/llm02_sensitive_disclosure.py`, `typescript/ai_vulnerabilities.ts` |
| **LLM03** | Supply Chain | `python/llm03_supply_chain.py` (+ main REACHABLE scan CVE/malware) |
| **LLM04** | Data and Model Poisoning | `python/llm04_to_llm10.py` |
| **LLM05** | Improper Output Handling | `python/llm05_output_handling.py`, `typescript/ai_vulnerabilities.ts` |
| **LLM06** | Excessive Agency | `python/llm06_excessive_agency.py`, `go/ai_vulnerabilities.go` |
| **LLM07** | System Prompt Leakage | `python/llm04_to_llm10.py` |
| **LLM08** | Vector & Embedding Weaknesses | `python/llm04_to_llm10.py` |
| **LLM09** | Misinformation | `python/llm04_to_llm10.py` |
| **LLM10** | Unbounded Consumption | `python/llm04_to_llm10.py` |
| **MCP**   | Model Context Protocol Security | `python/mcp_security.py`, `typescript/ai_vulnerabilities.ts` |
| **Garak** | Jailbreak Patterns (NVIDIA) | `python/garak_corpus_patterns.py` |

---

## OWASP Agentic Top 10:2026 Coverage

Released December 2025. Covers autonomous AI agents that plan, act, and make decisions.

| Category | Description | Test File |
|----------|-------------|-----------|
| **ASI01** | Agent Goal Hijack | `python/agentic_asi_2026.py` |
| **ASI02** | Tool Misuse & Exploitation | `python/agentic_asi_2026.py` |
| **ASI03** | Identity & Privilege Abuse | `python/agentic_asi_2026.py` |
| **ASI04** | Agentic Supply Chain Vulnerabilities | `python/agentic_asi_2026.py` |
| **ASI05** | Unexpected Code Execution (RCE) | `python/agentic_asi_2026.py` |
| **ASI06** | Memory & Context Poisoning | `python/agentic_asi_2026.py` |
| **ASI07** | Insecure Inter-Agent Communication | `python/agentic_asi_2026.py` |
| **ASI08** | Cascading Failures | `python/agentic_asi_2026.py` |
| **ASI09** | Human-Agent Trust Exploitation | `python/agentic_asi_2026.py` |
| **ASI10** | Rogue Agents | `python/agentic_asi_2026.py` |

---

## Test File Summary

| File | Framework | Vulnerable Patterns | Safe Patterns |
|------|-----------|---------------------|---------------|
| `python/llm01_prompt_injection.py` | LLM01:2025 | 6 | 2 |
| `python/llm02_sensitive_disclosure.py` | LLM02:2025 | 3 | 1 |
| `python/llm03_supply_chain.py` | LLM03:2025 | 4 | 1 |
| `python/llm04_to_llm10.py` | LLM04–LLM10:2025 | 14 | 3 |
| `python/llm05_output_handling.py` | LLM05:2025 | 3 | 1 |
| `python/llm06_excessive_agency.py` | LLM06:2025 | 4 | 2 |
| `python/mcp_security.py` | MCP | 4 | 1 |
| `python/garak_corpus_patterns.py` | LLM01:2025 | **43** | 0 |
| `python/agentic_asi_2026.py` | ASI01–ASI10:2026 | 20 | 5 |
| `typescript/ai_vulnerabilities.ts` | Mixed LLM:2025 | 10 | 2 |
| `go/ai_vulnerabilities.go` | Mixed LLM:2025 | 4 | 1 |

---

## Garak & Corpus Patterns

File `garak_corpus_patterns.py` contains **43 jailbreak patterns** from security research:

| Source | Rules | Pattern Types |
|--------|-------|---------------|
| **Garak** (NVIDIA) | 21 | DAN jailbreaks, prompt injection, encoding evasion, known signatures, training data extraction, XSS, malware generation |
| **Tensor Trust** | 7 | Access granted, system override, admin mode, security bypass |
| **JailbreakBench** | 7 | Evil confidant, fictional scenario, no limitations, content filter disable |
| **PromptInject** | 8 | Goal hijacking, prompt leaking, context manipulation, delimiter injection |

---

## Running Tests

```bash
# Full scan with AI analysis
reachctl scan ~/src/reach-testbed/ai-security-test --debug

# AI-only scan (skip CVE/secrets)
reachctl scan ~/src/reach-testbed/ai-security-test --no-dlp --debug

# Direct Semgrep test
semgrep --config reachable/ai/detectors/semgrep/ ~/src/reach-testbed/ai-security-test
```

---

## Expected Results

### By OWASP LLM:2025 Category

| Category | Min | Max | Notes |
|----------|-----|-----|-------|
| LLM01 | 40 | 60 | Prompt injection (43 Garak/Corpus patterns) |
| LLM02 | 2 | 5 | PII/credential exposure |
| LLM03 | 2 | 5 | Supply chain / dependency confusion |
| LLM04 | 2 | 4 | Data/model poisoning |
| LLM05 | 2 | 5 | eval(), exec(), HTML injection |
| LLM06 | 3 | 8 | Shell tools, file access |
| LLM07 | 2 | 4 | System prompt leakage |
| LLM08 | 2 | 4 | RAG/embedding injection |
| LLM09 | 1 | 3 | Misinformation/hallucination risks |
| LLM10 | 2 | 4 | Unbounded consumption/DoS |

### By OWASP Agentic:2026 Category

| Category | Min | Max | Notes |
|----------|-----|-----|-------|
| ASI01 | 3 | 6 | Goal hijack via indirect injection |
| ASI02 | 2 | 4 | Tool misuse / unrestricted tool access |
| ASI03 | 2 | 4 | Credential/privilege abuse |
| ASI04 | 1 | 3 | Agentic supply chain |
| ASI05 | 2 | 4 | LLM output → code execution |
| ASI06 | 2 | 4 | Memory/context poisoning |
| ASI07 | 1 | 3 | Insecure inter-agent comms |
| ASI08 | 1 | 3 | Cascading failure patterns |
| ASI09 | 1 | 2 | Human-agent trust exploitation |
| ASI10 | 1 | 2 | Rogue agent patterns |

---

## References

- [OWASP LLM Top 10:2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Top 10 for Agentic Applications:2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [MCP Security Guidelines](https://modelcontextprotocol.io/docs/security)
- [NVIDIA Garak](https://github.com/NVIDIA/garak)
- [Tensor Trust Dataset](https://github.com/HumanCompatibleAI/tensor-trust-data)
- [JailbreakBench](https://github.com/JailbreakBench/artifacts)
- [PromptInject](https://github.com/agencyenterprise/PromptInject)
