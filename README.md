# REACHABLE Test Bed

Comprehensive test repository demonstrating REACHABLE's multi-signal correlation capabilities.

---

## 🌟 Featured Demos: Supply Chain Attack Detection

> **The killer demos for investors** — Watch REACHABLE detect sophisticated supply chain attacks that traditional tools miss, across both npm and pip ecosystems.

### Shai-Hulud (npm) — postinstall hook attack

```bash
cd shai-hulud-simulation && ./run-comparison.sh
```

### Muad'Dib (pip) — setup.py cmdclass attack

```bash
cd muaddib-simulation && ./run-comparison.sh
```

### Detection Summary

| Tool | npm (Shai-Hulud) | pip (Muad'Dib) | Sees Attack Chain? |
|------|-----------------|----------------|-------------------|
| Semgrep | 5 warnings | 4 warnings | ❌ No |
| GuardDog | 3 alerts | 3 alerts | ❌ No |
| Trivy | 0 (blind) | 0 (blind) | ❌ No |
| Grype | 0 (blind) | 0 (blind) | ❌ No |
| **REACHABLE** | **1 CRITICAL** | **1 CRITICAL** | ✅ **Full chain** |

Both attacks follow the same pattern: install hook → credential theft → exfiltration. Only the entry mechanism differs (`postinstall` vs `cmdclass`). REACHABLE detects both via static analysis (GuardDog + Semgrep) correlated with dynamic sandbox results (honeypot access + blocked network).

### Key Metrics

- **7-8 raw signals** → **1 correlated critical finding** per attack
- **87.5% noise reduction**
- **Exfil chain proof**: credential read + outbound attempt = confirmed malicious
- **Actionable verdict: BLOCK INSTALLATION**

📖 [npm attack chain](shai-hulud-simulation/docs/ATTACK-CHAIN.md) · [pip attack chain](muaddib-simulation/README.md)

---

## Purpose

1. **Validation** - Prove REACHABLE detects what it claims
2. **Regression** - Ensure releases don't break functionality
3. **Demo** - Show customers real scan output
4. **Documentation** - Examples of all vulnerability types

## Test Cases

| Directory | Language | Features Tested |
|-----------|----------|-----------------|
| `shai-hulud-simulation/` | JavaScript | 🌟 **npm supply chain attack** - postinstall hook + sandbox detection |
| `muaddib-simulation/` | Python | 🌟 **pip supply chain attack** - setup.py cmdclass + sandbox detection |
| `ai-security-test/` | Python/TS/Go | 🤖 **AI/LLM security** - OWASP LLM Top 10, Garak, Corpus patterns |
| `python-app/` | Python | CVEs, secrets, reachability, malware patterns |
| `javascript-app/` | JS/TS | npm vulns, call graph, entrypoints |
| `go-app/` | Go | go.mod vulns, FFI detection |
| `java-maven/` | Java | Maven multi-module, Spring entrypoints |
| `java-gradle/` | Java/Kotlin | Gradle Kotlin DSL, Android |
| `kotlin-app/` | Kotlin | Coroutines, Android lifecycle |
| `polyglot-monorepo/` | Mixed | Cross-language, microservices |
| `malware-test-packages/` | JavaScript | GuardDog malware pattern detection |

## AI Security Tests 🤖

The `ai-security-test/` directory contains test cases for AI/LLM security detection:

| File | Patterns | Detection |
|------|----------|----------|
| `python/llm01_prompt_injection.py` | Direct prompt injection | OWASP LLM01 |
| `python/llm02_sensitive_disclosure.py` | Sensitive data leakage | OWASP LLM02 |
| `python/llm05_output_handling.py` | Unsafe output (exec, eval) | OWASP LLM05 |
| `python/llm06_excessive_agency.py` | Unrestricted tool access | OWASP LLM06 |
| `python/mcp_security.py` | MCP tool security | MCP violations |
| `python/garak_corpus_patterns.py` | **43 jailbreak patterns** | Garak + Corpus rules |
| `typescript/ai_vulnerabilities.ts` | TypeScript AI patterns | Multi-language |
| `go/ai_vulnerabilities.go` | Go AI patterns | Multi-language |

### Garak & Corpus Patterns

The `garak_corpus_patterns.py` file tests 47 new rules derived from:

| Source | Rules | Examples |
|--------|-------|----------|
| **Garak** (NVIDIA) | 25 | DAN jailbreaks, prompt injection, encoding evasion |
| **Tensor Trust** | 7 | Access granted, system override, admin mode |
| **JailbreakBench** | 7 | Evil confidant, fictional bypass, unfiltered requests |
| **PromptInject** | 8 | Goal hijacking, prompt leaking, delimiter injection |

### Running AI Security Tests

```bash
# Standard scan (AI analysis included by default)
reachctl scan ai-security-test/

# Scan with debug output
reachctl scan ai-security-test/ --debug

# Skip AI analysis for faster scans
reachctl scan ai-security-test/ --no-ai

# Validate against expected results
python validate.py results/ai-security.json expected-results/ai-garak-corpus-expected.json
```

### Expected Output

- **~107 total AI findings** across all test files
- **47 findings** from Garak/Corpus patterns alone
- Output files: `ai-security.json`, `ai-security.sarif`

---

## Malware Detection Tests

The `malware-test-packages/` directory contains safe simulations of malicious patterns:

| Package | Simulated Behavior | Detection |
|---------|-------------------|-----------|
| `fake-c2-beacon` | C2 server communication | Network monitoring |
| `fake-data-exfil` | Credential theft | File access + network |
| `fake-cryptominer` | Mining pool connections | Network monitoring |
| `fake-reverse-shell` | Reverse shell spawn | Process + network |
| **`shai-hulud-simulation`** | **Full supply chain attack** | **Multi-signal correlation** |

## Expected Results

Each test case has a corresponding `expected-results/*.json` file with:
- Expected CVE count (reachable vs total)
- Expected secrets count
- Expected entrypoints
- Expected risk level

## Quick Start

```bash
# Run the flagship demo
cd shai-hulud-simulation && ./run-comparison.sh

# Run all validations
./run-tests.sh

# Run single test case
reachctl scan python-app/ --output results/python/
```

## Validation Workflow

```bash
# Run REACHABLE on test case
reachctl scan python-app/ --json > actual.json

# Compare with expected
python validate.py actual.json expected-results/python-app.json
```

## CI/CD Integration

The `.github/workflows/validate.yml` workflow:
1. Runs REACHABLE on each test case
2. Compares output to expected results
3. Fails if detection rates drop

## Test Case Details

### shai-hulud-simulation/ ⭐ NEW
- **Multi-stage supply chain attack** simulation
- **postinstall hook** → loader → harvester → exfiltration
- **7 correlated signals** → 1 critical finding
- Demonstrates REACHABLE's unique value proposition

### python-app/
- **CVE-2021-44228** - Log4Shell (transitive via py4j) - UNREACHABLE
- **CVE-2022-42969** - py-pdf ReDoS - REACHABLE
- **Hardcoded AWS key** - In reachable code path
- **Dead secret** - Revoked key in unreachable function

### javascript-app/
- **CVE-2021-23337** - lodash prototype pollution - REACHABLE
- **CVE-2020-28469** - glob-parent ReDoS - UNREACHABLE
- **npm malware pattern** - base64 decode + eval

### java-maven/
- **CVE-2022-22965** - Spring4Shell - REACHABLE via @PostMapping
- **CVE-2021-42392** - H2 Console RCE - UNREACHABLE (test scope)
- Multi-module with parent POM inheritance

### go-app/
- **CVE-2022-32149** - golang.org/x/text DoS - REACHABLE
- **CGO boundary** - Unsafe C call detection

## Adding New Test Cases

1. Create directory with vulnerable code
2. Document expected CVEs in README
3. Add `expected-results/{name}.json`
4. Update validation workflow

## License

**© 2026 Sthenos Security. All rights reserved.**

Created by Alain Dazzi | adazzi@sthenosec.com
