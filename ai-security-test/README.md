# AI Security Test Cases for REACHABLE
# Copyright © 2026 Sthenos Security. All rights reserved.

This directory contains intentionally vulnerable AI/LLM code for testing
REACHABLE's AI security scanner (OWASP LLM Top 10).

## Test Coverage

### OWASP LLM Top 10

| Category | Description | Test Files |
|----------|-------------|------------|
| **LLM01** | Prompt Injection | `python/llm01_prompt_injection.py`, `typescript/ai_vulnerabilities.ts` |
| **LLM02** | Sensitive Information Disclosure | `python/llm02_sensitive_disclosure.py`, `typescript/ai_vulnerabilities.ts` |
| **LLM03** | Supply Chain | (covered by main REACHABLE scan) |
| **LLM05** | Improper Output Handling | `python/llm05_output_handling.py`, `typescript/ai_vulnerabilities.ts` |
| **LLM06** | Excessive Agency | `python/llm06_excessive_agency.py`, `go/ai_vulnerabilities.go` |
| **MCP** | Model Context Protocol Security | `python/mcp_security.py`, `typescript/ai_vulnerabilities.ts` |
| **Garak** | Jailbreak Patterns (NVIDIA) | `python/garak_corpus_patterns.py` |
| **Corpus** | Research Datasets | `python/garak_corpus_patterns.py` |

### Test File Summary

| File | OWASP | Vulnerable Patterns | Safe Patterns |
|------|-------|---------------------|---------------|
| `python/llm01_prompt_injection.py` | LLM01 | 6 | 2 |
| `python/llm02_sensitive_disclosure.py` | LLM02 | 3 | 1 |
| `python/llm05_output_handling.py` | LLM05 | 3 | 1 |
| `python/llm06_excessive_agency.py` | LLM06 | 4 | 2 |
| `python/mcp_security.py` | MCP | 4 | 1 |
| `python/garak_corpus_patterns.py` | LLM01 | **43** | 0 |
| `typescript/ai_vulnerabilities.ts` | Mixed | 10 | 2 |
| `go/ai_vulnerabilities.go` | Mixed | 4 | 1 |

### Garak & Corpus Patterns (garak_corpus_patterns.py)

This file contains **43 jailbreak patterns** derived from security research:

| Source | Rules | Pattern Types |
|--------|-------|---------------|
| **Garak** (NVIDIA) | 21 | DAN jailbreaks, prompt injection, encoding evasion, known signatures, training data extraction, XSS, malware generation, LMRC |
| **Tensor Trust** | 7 | Access granted, system override, admin mode, security bypass, hidden features, secret reveal, safety ignore |
| **JailbreakBench** | 7 | Evil confidant, fictional scenario, no limitations, content filter disable, no ethics, research bypass, unfiltered response |
| **PromptInject** | 8 | Goal hijacking, prompt leaking, context manipulation, identity change, delimiter injection, token boundary, debug mode, jailbreak completion |

Expected findings from `expected-results/ai-garak-corpus-expected.json`.

## Running Tests

### Option 1: Full Scan with AI Analysis
```bash
cd ~/src/reach-core
./reachctl scan ~/src/reach-testbed/ai-security-test --enable-ai --debug
```

### Option 2: AI-Only Scan (Skip CVE/Secrets)
```bash
./reachctl scan ~/src/reach-testbed/ai-security-test --ai-only --debug
```

### Option 3: Direct Semgrep Test
```bash
cd ~/src/reach-core
semgrep --config reachable/ai/detectors/semgrep/ ~/src/reach-testbed/ai-security-test
```

### Option 4: Unit Tests
```bash
cd ~/src/reach-core
python -m pytest tests/test_ai_scanner.py -v
```

## Expected Results

### Total Findings
- **Minimum**: 50 findings (with Garak/Corpus)
- **Maximum**: 80 findings
- **Critical (unguarded)**: 10-20 findings

### By OWASP Category

| Category | Min | Max | Notes |
|----------|-----|-----|-------|
| LLM01 | 40 | 60 | Prompt injection (includes 43 Garak/Corpus patterns) |
| LLM02 | 2 | 5 | PII/credential exposure |
| LLM05 | 2 | 5 | eval(), exec(), HTML injection |
| LLM06 | 3 | 8 | Shell tools, file access |
| MCP | 2 | 6 | Insecure tool registration |

### By Severity

| Severity | Min | Max |
|----------|-----|-----|
| ERROR | 5 | 15 |
| WARNING | 5 | 15 |
| INFO | 0 | 5 |

## Validating Detection

After running `--enable-ai` scan:

1. **Check Output File**
   ```bash
   cat ~/.reachable/scans/ai-security-test-*/latest/ai-security.json | jq '.by_owasp'
   ```

2. **Verify No False Positives**
   - `safe_sanitized_input` → should NOT trigger ERROR
   - `safe_hardcoded_prompt` → should NOT trigger ERROR
   - `SafeMCPServer` → should NOT trigger ERROR
   - `safeRestrictedShell` → should NOT trigger ERROR

3. **Verify All Vulnerable Patterns Found**
   - `vulnerable_chat_direct_input` → should trigger LLM01
   - `vulnerable_f_string_injection` → should trigger LLM01
   - `vulnerable_system_prompt_override` → should trigger LLM01
   - `VulnerableMCPServer` → should trigger MCP findings
   - `DAN_JAILBREAK_1` → should trigger garak-dan-001
   - `IGNORE_PREVIOUS` → should trigger garak-promptinject-001
   - `ACCESS_GRANTED` → should trigger corpus-tensortrust-001
   - `EVIL_CONFIDANT` → should trigger corpus-jailbreakbench-001

## Frameworks Covered

### Python
- `openai` (OpenAI SDK)
- `anthropic` (Anthropic SDK)
- `langchain` (LangChain)
- `llama_index` (LlamaIndex)

### TypeScript/JavaScript
- `openai` (OpenAI SDK)
- `@anthropic-ai/sdk` (Anthropic SDK)
- `@langchain/openai` (LangChain)
- `@langchain/core` (LangChain Core)

### Go
- `sashabaranov/go-openai`
- `tmc/langchaingo`

## Adding New Test Cases

1. Create new file in appropriate language directory
2. Add OWASP category comments
3. Include both VULNERABLE and SAFE patterns
4. Update this README with expected counts
5. Update `expected-results/ai-security-expected.json`
6. Run tests to validate

### Template for New Test File
```python
# LLM0X - [Category Name] Test Cases
# INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
# Copyright © 2026 Sthenos Security. Test file only.

"""
This file contains intentionally vulnerable code patterns that should
trigger LLM0X ([Category Name]) detections.
"""

# === VULNERABLE: Pattern Name ===
def vulnerable_pattern_name():
    # BAD: Description of vulnerability
    pass

# === SAFE: Safe version ===
def safe_pattern_name():
    # GOOD: Why this is safe
    pass
```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: AI Security Scan
  run: |
    ./reachctl scan . --enable-ai --fail-on high --quiet
    
- name: Upload AI Security Report
  uses: actions/upload-artifact@v4
  with:
    name: ai-security-report
    path: ~/.reachable/scans/*/latest/ai-security.json
```

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MCP Security Guidelines](https://modelcontextprotocol.io/docs/security)
- [LangChain Security Best Practices](https://python.langchain.com/docs/security)
- [NVIDIA Garak](https://github.com/NVIDIA/garak) - LLM vulnerability scanner
- [Tensor Trust](https://github.com/HumanCompatibleAI/tensor-trust-data) - Prompt injection game dataset
- [JailbreakBench](https://github.com/JailbreakBench/artifacts) - Curated jailbreak prompts
- [PromptInject](https://github.com/agencyenterprise/PromptInject) - Academic prompt injection dataset
