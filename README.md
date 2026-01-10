# REACHABLE Test Bed

Comprehensive test repository demonstrating REACHABLE's multi-signal correlation capabilities.

---

## 🌟 Featured Demo: Shai-Hulud Supply Chain Attack

> **The killer demo for investors** - Watch REACHABLE detect a sophisticated supply chain attack that traditional tools miss.

```bash
cd shai-hulud-simulation
./run-comparison.sh
```

### What You'll See

| Tool | Findings | Actionable? | Sees Attack Chain? |
|------|----------|-------------|-------------------|
| Semgrep | 5 warnings | ❌ No context | ❌ No |
| GuardDog | 3 alerts | ❌ No context | ❌ No |
| Trivy | 0 | ❌ Blind | ❌ No |
| Grype | 0 | ❌ Blind | ❌ No |
| **REACHABLE** | **1 CRITICAL** | ✅ **Yes** | ✅ **Full chain** |

### The Attack Chain

```
npm install
     │
     ▼
[postinstall] ──► loader.js ──► harvester.js ──► Steal credentials
                      │              │                  │
                      │              ▼                  │
                      │         ~/.npmrc               │
                      │         ~/.ssh/*               │
                      │         ~/.aws/*               │
                      │                                │
                      └──────► exfil.js ◄──────────────┘
                                   │
                                   ▼
                            Attacker C2 server
```

### Key Metrics

- **7 raw signals** → **1 correlated critical finding**
- **87.5% noise reduction**
- **Full attack chain visibility**
- **Actionable verdict: BLOCK INSTALLATION**

📖 [Full attack chain documentation](shai-hulud-simulation/docs/ATTACK-CHAIN.md)  
📊 [Tool comparison matrix](shai-hulud-simulation/docs/COMPARISON-MATRIX.md)

---

## Purpose

1. **Validation** - Prove REACHABLE detects what it claims
2. **Regression** - Ensure releases don't break functionality
3. **Demo** - Show customers real scan output
4. **Documentation** - Examples of all vulnerability types

## Test Cases

| Directory | Language | Features Tested |
|-----------|----------|-----------------|
| `shai-hulud-simulation/` | JavaScript | 🌟 **Supply chain attack demo** - multi-signal correlation |
| `python-app/` | Python | CVEs, secrets, reachability, malware patterns |
| `javascript-app/` | JS/TS | npm vulns, call graph, entrypoints |
| `go-app/` | Go | go.mod vulns, FFI detection |
| `java-maven/` | Java | Maven multi-module, Spring entrypoints |
| `java-gradle/` | Java/Kotlin | Gradle Kotlin DSL, Android |
| `kotlin-app/` | Kotlin | Coroutines, Android lifecycle |
| `polyglot-monorepo/` | Mixed | Cross-language, microservices |
| `malware-test-packages/` | JavaScript | GuardDog malware pattern detection |

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
