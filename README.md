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
| `private-registry/` | Py/JS/Go/Java | 🆕 **Private registry resolution** — PURLResolver + lib_manager |
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

---

## Private Registry Integration Tests

The `private-registry/` directory validates that REACHABLE correctly handles projects pulling from both public registries and private Docker-based registries in the same scan.

This proves three things:
1. **Scan correctness** — reachctl scan completes with exit 0, no fatal tool errors, SBOM populated, repo.db consistent
2. **Public + private coexistence** — public packages resolve normally alongside private registry packages
3. **Auth enforcement** — private packages require proper authentication; bad/missing auth is rejected

### Infrastructure

```
private-registry/
├── docker-compose.yml          # 4 registry services
│   ├── devpi        (Python)   → localhost:3141
│   ├── verdaccio    (npm)      → localhost:4873
│   ├── athens       (Go)      → localhost:3000
│   └── reposilite   (Maven)   → localhost:8081
├── setup-and-test.sh           # One-command: start → publish → install → test
├── setup.sh                    # Populate registries with test packages
├── teardown.sh                 # Stop + remove containers and volumes
├── verdaccio-config.yaml       # Verdaccio auth + proxy config
├── registries-test.yaml        # REACHABLE registry config for tests
└── target-projects/            # Reference mixed-registry projects
    ├── python-mixed/           # requirements.txt + pip.conf (with devpi)
    ├── npm-mixed/              # package.json + .npmrc (with Verdaccio)
    ├── go-mixed/               # go.mod + main.go (with Athens)
    ├── maven-mixed/            # pom.xml + settings.xml (with Reposilite)
    ├── npm-noauth/             # Negative test: NO Verdaccio auth
    └── python-noauth/          # Negative test: NO devpi auth
```

### Test Files

```
tests/
├── test_private_registry_integration.py   # 88 tests: full reachctl scan validation
│   ├── TestPythonMixed*       (16 tests)  # Exit, log, SBOM, DB, cache, raw files
│   ├── TestNpmMixedScan       (16 tests)  # Exit, log, SBOM (public + @company/*)
│   ├── TestGoMixedScan         (8 tests)  # Exit, log, SBOM, PURLs
│   ├── TestMavenMixedScan     (12 tests)  # Exit, log, SBOM, PURLs, DB
│   ├── TestCacheIntegrity      (7 tests)  # Cross-ecosystem cache/DB
│   ├── TestDatabaseSchema      (3 tests)  # repo.db table/schema validation
│   ├── TestNpmNoAuth           (7 tests)  # Negative: public ✓, @company/* ✗
│   └── TestPythonNoAuth        (5 tests)  # Negative: public ✓, internal-sdk ✗
├── test_registry_auth.py                  # 27 tests: HTTP-level auth validation
│   ├── TestArtifactory*       (13 tests)  # Mock JFrog: good/none/bad auth × 4 langs
│   ├── TestVerdaccioAuth       (4 tests)  # Live npm registry auth
│   ├── TestDevpiAuth           (3 tests)  # Live Python registry auth
│   ├── TestReposiliteAuth      (5 tests)  # Live Maven registry auth (deploy auth)
│   └── TestAthensAuth          (2 tests)  # Live Go proxy (public by design)
└── conftest.py                            # Session fixtures, scan runner, ScanResult
```

### Quick Start (One Command)

```bash
# Everything: start Docker, publish packages, install deps, run all tests
cd private-registry
./setup-and-test.sh
```

Or step by step:

```bash
# Setup only (no tests)
./setup-and-test.sh setup

# Tests only (assumes setup done)
./setup-and-test.sh test
```

### Running Specific Test Suites

```bash
# Full integration suite (88 tests — runs reachctl scan per ecosystem)
pytest tests/test_private_registry_integration.py -v --tb=short

# Registry auth tests (27 tests — fast, mock Artifactory + live registries)
pytest tests/test_registry_auth.py -v --tb=short

# Both suites together
pytest tests/test_registry_auth.py tests/test_private_registry_integration.py -v --tb=short

# Per-ecosystem
pytest tests/test_private_registry_integration.py -v -k "Npm"       # npm only
pytest tests/test_private_registry_integration.py -v -k "Go"        # Go only
pytest tests/test_private_registry_integration.py -v -k "Maven"     # Maven only
pytest tests/test_private_registry_integration.py -v -k "Python"    # Python only

# Negative tests only (proves auth matters)
pytest tests/test_private_registry_integration.py -v -k "NoAuth"

# Mock Artifactory only (no Docker needed — always passes)
pytest tests/test_registry_auth.py -v -k "Artifactory"

# Live registry auth only
pytest tests/test_registry_auth.py -v -k "Verdaccio or Devpi or Reposilite or Athens"

# With live output (see scan progress)
pytest tests/test_private_registry_integration.py -v -s --tb=short
```

### Test Matrix

#### Positive Tests (per ecosystem)

Each ecosystem is tested with a 6-layer validation strategy:

| Layer | What | Example Assertion |
|-------|------|-------------------|
| 1. Exit code | Scan completed | `exit_code == 0` |
| 2. Scan log | No fatal tool errors | No `FATAL`, `Traceback` in log |
| 3. SBOM | Public + private packages present | `express` in names, `@company/logger` in names |
| 4. Database | Scan status complete, findings populated | `scans.status = 'complete'` |
| 5. Cache | Libs directory and global cache populated | `libs/` exists |
| 6. Raw files | scan-manifest.json, cve-analyzed.json exist | File presence |

Package types per scan:

| Type | Example | In SBOM? | CVEs? |
|------|---------|----------|-------|
| **Public** | `express@4.18.2` | ✅ | ✅ |
| **Private wrapper** | `@company/logger@2.0.0` (wraps winston) | ✅ | Via resolver |
| **Genuine private** | `@company/internal-utils@3.0.0` | ✅ | ❌ (no upstream) |

#### Negative Tests (auth enforcement)

| Test | Public packages | Private packages | Proves |
|------|----------------|-----------------|--------|
| `npm-noauth` | express ✅, lodash ✅ | @company/* ❌ | Auth required for private |
| `python-noauth` | requests ✅, flask ✅ | internal-sdk ❌ | Auth required for private |

#### Auth Tests (3-tier per registry type)

| Registry | Good auth → | No auth → | Bad auth → |
|----------|------------|-----------|------------|
| **Mock Artifactory npm** | 200 | 401 | 403 |
| **Mock Artifactory PyPI** | 200 | 401 | 403 |
| **Mock Artifactory Maven** | 200 | 401 | 403 |
| **Mock Artifactory Go** | 200 | 401 | 403 |
| **Live Verdaccio** | 200/404 | 200 (public) | Depends on config |
| **Live Reposilite** | 200/201 (deploy) | 401/403 (deploy) | 401/403 |

### Mock JFrog Artifactory

The auth test suite includes a mock JFrog Artifactory server that simulates the unified proxy pattern used by enterprise customers (e.g., Roku). It uses real Artifactory URL layouts:

| Ecosystem | Artifactory URL Pattern | Auth Method |
|-----------|------------------------|-------------|
| npm | `/artifactory/api/npm/npm-local/` | Bearer token in header |
| PyPI | `/artifactory/api/pypi/pypi-local/simple/` | Basic auth (user:token) |
| Maven | `/artifactory/maven-local/` | Basic auth (from settings.xml) |
| Go | `/artifactory/api/go/go-local/` | Bearer token via GOPROXY URL |

The mock runs in-process (no Docker) and verifies all 13 auth scenarios in ~0.1s.

### Prerequisites

- Docker + Docker Compose
- Python 3.10+, pip, npm, Go 1.21+ (Maven optional — Syft parses pom.xml directly)
- reach-core installed (`pip install -e ~/src/reach-core`)

```
~/src/
├── reach-core/      # pip install -e .
└── reach-testbed/   # this repo
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEVPI_URL` | `http://localhost:3141` | Python registry URL |
| `VERDACCIO_URL` | `http://localhost:4873` | npm registry URL |
| `ATHENS_URL` | `http://localhost:3000` | Go proxy URL |
| `REPOSILITE_URL` | `http://localhost:8081` | Maven registry URL |

### Troubleshooting

```bash
# Check which services are running
docker compose -f private-registry/docker-compose.yml ps

# View registry logs
docker logs private-registry-verdaccio-1 --tail 20
docker logs private-registry-reposilite-1 --tail 20

# Restart everything clean
cd private-registry && docker compose down -v && ./setup-and-test.sh

# Run tests with live scan output visible
pytest tests/test_private_registry_integration.py -v -s
```

> **Unit tests** for the same features (no Docker) live in `reach-core/tests/unit/`.

---

## Adding New Test Cases

1. Create directory with vulnerable code
2. Document expected CVEs in README
3. Add `expected-results/{name}.json`
4. Update validation workflow

## License

**© 2026 Sthenos Security. All rights reserved.**

Created by Alain Dazzi | info@sthenosec.com
