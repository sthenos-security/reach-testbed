# REACHABLE Test Bed

Comprehensive test repository demonstrating REACHABLE's multi-signal correlation capabilities.

This is an intentionally vulnerable test corpus for security framework testing — do not use in production

---

## 🌟 Featured Demos: Supply Chain Attack Detection

> **The killer demos ** — Watch REACHABLE detect sophisticated supply chain attacks that traditional tools miss, across both npm and pip ecosystems.

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

## Scan Baseline (v1.0.0b36)

> `reachctl scan ~/src/reach-testbed` · 2026-03-15 · v1.0.0b36

| Signal | Total | Exploitable | Unverified | Filtered |
|--------|------:|------------:|-----------:|---------:|
| CVE | 103 | 63 | 0 | 40 |
| CWE | 458 | 217 | 164 | 77 |
| SECRET | 112 | 34 | 46 | 32 |
| DLP | 67 | 67 | 0 | 0 |
| AI/LLM | 183 | 55 | 0 | 128 |
| MALWARE | 274 | 122 | 0 | 152 |
| CONFIG | 134 | — | — | — |
| **TOTAL** | **1331** | **558** | **210** | **429** |

**Noise reduction: 36.6%** (base scan) · **56.5%** with `--ai-enhance`

Add `--ai-enhance` for AI-verified exploitability across CWE, secrets, DLP, and AI/LLM findings.

See [SIGNAL-INVENTORY.md](SIGNAL-INVENTORY.md) for full breakdown including AI per-signal metrics.

---

## Purpose

1. **Validation** - Prove REACHABLE detects what it claims
2. **Regression** - Ensure releases don't break functionality
3. **Demo** - Show customers real scan output
4. **Documentation** - Examples of all vulnerability types

## Repository Structure

```
reach-testbed/
├── testbed.json               # Ground-truth assertions (v1.6, 134 reachability entries)
├── validate.py                # Validation runner — checks scan output against testbed.json
├── SIGNAL-INVENTORY.md        # Full signal inventory with R/NR/U counts per test app
├── docs/
│   └── FRAMEWORK-COVERAGE-GAPS.md  # Framework coverage analysis and gap closure status
│
├── ── Featured Demos ──────────────────────────────────────────────
├── shai-hulud-simulation/     # 🌟 npm supply chain attack (postinstall → exfil)
├── muaddib-simulation/        # 🌟 pip supply chain attack (setup.py cmdclass → exfil)
│
├── ── Core Language Apps ──────────────────────────────────────────
├── python-app/                # Python: CVEs, secrets, reachability, malware patterns
├── javascript-app/            # JS/TS: npm vulns, call graph, entrypoints
├── go-app/                    # Go: go.mod vulns, FFI detection
├── java-maven/                # Java: Maven multi-module, Spring entrypoints
├── java-gradle/               # Java/Kotlin: Gradle Kotlin DSL, Android
├── kotlin-app/                # Kotlin: coroutines, Android lifecycle
├── typescript-app/            # TypeScript: TS-specific patterns
├── ruby-app/                  # Ruby: Bundler vulns
├── rust-app/                  # Rust: Cargo vulns
├── scala-app/                 # Scala: SBT/Maven vulns
├── groovy-app/                # Groovy: Grape/Gradle vulns
│
├── ── Framework Test Apps (new in v1.6) ───────────────────────────
├── django-app/                # Django + DRF: FBV/CBV/ViewSet, urlpatterns wiring
├── fastapi-app/               # FastAPI: APIRouter, include_router, Depends
├── pyramid-app/               # Pyramid: config.add_route + config.add_view
├── nestjs-app/                # NestJS: @Module/@Controller/@Injectable decorators
├── fastify-app/               # Fastify: fastify.register plugin model
├── hono-app/                  # Hono: app.route() chaining
├── echo-app/                  # Echo (Go): e.POST/e.GET/e.Group registration
│
├── ── Signal & Reachability Tests ─────────────────────────────────
├── signal-matrix/             # 🎯 All 6 signals × 4 languages × 3 reachability states
├── invocation-patterns/       # 🔄 External endpoint vs internal trigger vs dead code
├── reachability-states-test/  # Basic R/NR state verification
├── npm-callgraph-test/        # 🔬 JS call graph canary (node-serialize, semver)
├── java-callgraph-test/       # 🔬 Java call graph canary (Log4Shell vs Text4Shell)
├── client-side-app/           # React client-side reachability
├── transitive-dep-tests/      # Transitive dependency resolution
├── site-packages-test/        # site-packages exclusion validation
│
├── ── Signal-Specific Tests ───────────────────────────────────────
├── cwe-tests/                 # CWE patterns incl. SQL injection variable origin matrix
├── secret-tests/              # Secret detection patterns
├── secrets-tests/             # Additional secret patterns
├── cve-group-tests/           # CVE group detection (Pillow, cryptography, paramiko)
├── ai-security-test/          # 🤖 AI/LLM security: OWASP LLM Top 10, Garak, Corpus
├── malware-test-packages/     # GuardDog malware pattern detection
├── static-malware-tests/      # Static malware analysis patterns
├── dlp-tests/                 # DLP/PII detection patterns
├── iac-tests/                 # Infrastructure-as-code misconfigurations
├── grc-tests/                 # GRC/compliance patterns
├── signature-tests/           # Custom signature rule tests
├── osv-enrichment-test/       # OSV database enrichment
│
├── ── Infrastructure Tests ────────────────────────────────────────
├── private-registry/          # Private registry resolution (devpi, Verdaccio, Athens, Reposilite)
├── polyglot-monorepo/         # Cross-language microservices
├── noisy-enterprise-app/      # Large noisy repo for noise reduction testing
├── invalid-encoding-test/     # Non-UTF8 file handling
│
├── ── Support ─────────────────────────────────────────────────────
├── expected-results/          # JSON files with expected scan output per test app
├── policies/                  # Custom policy files for GRC/compliance testing
├── scripts/                   # Helper scripts
└── tests/                     # pytest integration tests (private registry, auth)
```

## Test Cases

| Directory | Language | Features Tested |
|-----------|----------|-----------------|
| `shai-hulud-simulation/` | JavaScript | 🌟 **npm supply chain attack** - postinstall hook + sandbox detection |
| `muaddib-simulation/` | Python | 🌟 **pip supply chain attack** - setup.py cmdclass + sandbox detection |
| `ai-security-test/` | Python/TS/Go | 🤖 **AI/LLM security** - OWASP LLM Top 10, Garak, Corpus patterns |
| `python-app/` | Python | CVEs, secrets, reachability, malware patterns |
| `npm-callgraph-test/` | JavaScript | 🔬 **JS call graph canary** — REACHABLE vs NOT_REACHABLE npm CVEs (node-serialize, semver) |
| `java-callgraph-test/` | Java | 🔬 **Java call graph canary** — Log4Shell REACHABLE, Text4Shell in dead class NOT_REACHABLE |
| `javascript-app/` | JS/TS | npm vulns, call graph, entrypoints |
| `go-app/` | Go | go.mod vulns, FFI detection |
| `java-maven/` | Java | Maven multi-module, Spring entrypoints |
| `java-gradle/` | Java/Kotlin | Gradle Kotlin DSL, Android |
| `kotlin-app/` | Kotlin | Coroutines, Android lifecycle |
| `polyglot-monorepo/` | Mixed | Cross-language, microservices |
| `private-registry/` | Py/JS/Go/Java | **Private registry resolution** — PURLResolver + lib_manager |
| `malware-test-packages/` | JavaScript | GuardDog malware pattern detection |
| `signal-matrix/` | Py/JS/Go/Java | 🎯 **Full signal matrix** — all 6 signals × 4 languages × 3 reachability states |
| `invocation-patterns/` | Py/JS/Go/Java | 🔄 **Invocation patterns** — external endpoint vs internal trigger vs dead code × 4 languages |
| `cwe-tests/python/cwe_sqli_matrix.py` | Python | 🧪 **SQL injection variable origin matrix** — 7 TP + 8 FP + 3 TN + 4 edge cases |
| `django-app/` | Python | 🆕 **Django + DRF** — FBV, CBV, ViewSet, dead views not in urlpatterns |
| `fastapi-app/` | Python | 🆕 **FastAPI** — APIRouter, include_router, dead routers never mounted |
| `pyramid-app/` | Python | 🆕 **Pyramid** — config.add_route/add_view, @view_config with no matching route |
| `nestjs-app/` | TypeScript | 🆕 **NestJS** — @Module/@Controller/@Injectable, dead controllers not in AppModule |
| `fastify-app/` | JavaScript | 🆕 **Fastify** — plugin registration model, dead plugins never registered |
| `hono-app/` | TypeScript | 🆕 **Hono** — app.route() chaining, dead routes never mounted |
| `echo-app/` | Go | 🆕 **Echo** — e.POST/e.GET/e.Group, dead handlers never registered |

## Call Graph Canaries 🔬

Two test cases exist specifically to detect if a language call graph is broken or silently disabled. If either fires as `UNKNOWN` instead of the expected `NOT_REACHABLE`, a regression has occurred.

| Test | Package | Expected | Canary for | Failure means |
|------|---------|----------|------------|---------------|
| `npm-callgraph-test/src/utils/serializer.js` | node-serialize 0.0.4 | `NOT_REACHABLE` | JS call graph | `JSCallGraphCollector` broken/disabled |
| `npm-callgraph-test/src/utils/version_check.js` | semver 5.7.1 | `NOT_REACHABLE` | JS call graph | Call graph not tracing dead-code islands |
| `java-callgraph-test/.../DeadCodeService.java` | commons-text 1.9 | `NOT_REACHABLE` | Java call graph | Java call graph broken/disabled |

---

## Signal Matrix 🎯

`signal-matrix/` is the authoritative coverage matrix: every signal type tested in all 3 reachability states across all 4 supported languages. Scan it to confirm REACHABLE produces correct results for every combination before any release.

### Coverage

| Signal   | Python R/NR/U | JS R/NR/U | Go R/NR/U | Java R/NR/U |
|----------|:-------------:|:---------:|:---------:|:-----------:|
| CVE      | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ |
| CWE      | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ |
| SECRET   | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ |
| DLP      | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ |
| AI       | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ |
| MALWARE  | ✅/✅/✅ | ✅/✅/✅ | ✅/✅/✅ | NR only |

R=REACHABLE · NR=NOT_REACHABLE · U=UNKNOWN

### Structure

Each language has an entrypoint that orchestrates reachability:

- **REACHABLE** — vulnerable function on a live call path from the entrypoint
- **NOT_REACHABLE** — module/file/class completely absent from the import/call graph
- **UNKNOWN** — module IS imported/instantiated but the specific vulnerable function is never invoked (import graph hit, call graph miss)

```
signal-matrix/
├── python/
│   ├── entrypoint.py          # Flask app — imports R+U modules, never imports NR modules
│   └── signals/
│       ├── {signal}_reachable.py       # called from entrypoint
│       ├── {signal}_not_reachable.py   # never imported
│       └── {signal}_unknown.py         # imported but only safe fn called
├── javascript/
│   ├── server.js              # Express app — same pattern
│   └── signals/
│       ├── {signal}_reachable.js
│       ├── {signal}_not_reachable.js
│       └── {signal}_unknown.js
├── go/
│   ├── main.go                # gin router
│   └── signals/
│       ├── cve.go             # REACHABLE TranslateHandler + UNKNOWN ParseLangUnknown
│       ├── cve_dead.go        # NOT_REACHABLE ParseYamlDead
│       ├── cwe.go / secret.go / dlp.go / ai.go / malware.go
└── java/
    └── src/main/java/com/example/
        ├── ReachableController.java   # @RestController — all REACHABLE signals
        ├── UnknownController.java     # @RestController — safe HTTP routes, vuln in private methods
        ├── DlpAiController.java       # @RestController — DLP + AI REACHABLE
        └── DeadCodeService.java       # NO @Component — never instantiated, all NOT_REACHABLE
```

### Expected results

See `expected-results/signal-matrix.json` for the complete validation spec. The `canary: true` entries are the highest-priority checks — a wrong result there indicates a call graph or reachability engine regression.

### UNKNOWN semantics

UNKNOWN is the correct result when REACHABLE cannot determine reachability from static analysis alone (e.g. the vulnerable function exists in an imported module but has no static call path from any entrypoint). It is **not** a failure. What IS a failure:
- A known REACHABLE function showing NOT_REACHABLE (missed detection)
- A known NOT_REACHABLE function showing REACHABLE (false positive)
- An UNKNOWN function showing REACHABLE without a confirmed call path (false positive)

### Why these are canaries

Without a call graph, REACHABLE falls back to `UNKNOWN` for all packages that are in the SBOM but whose source files are never directly analysed. The canary packages are engineered so that:
- Their source files **exist** in the repo (so Grype finds them in the SBOM)
- Their source files are **never imported/instantiated** from any entrypoint
- The only way to get `NOT_REACHABLE` is for the call graph to have actually traced the import/call graph and found no path

If either canary regresses to `UNKNOWN`, check: `JSCallGraphCollector.is_available()`, the JS call graph step in `pipeline_finalize`, and the Java Joern/call graph collector output.

---

## Invocation Patterns 🔄

`invocation-patterns/` tests the three fundamental ways code can execute, across all 4 languages. This validates both the deterministic call graph and the AI reachability analyzer (`enzo analyze`).

### The Three Cases

| Case | Pattern | Expected | RA Today | AI |
|------|---------|----------|----------|----|
| 1. External endpoint | HTTP route → sink | REACHABLE | ✅ | ✅ Confirms taint |
| 2. Internal trigger | thread/timer/init → sink | REACHABLE | ❌ **Gap** | ⚠️ Can classify |
| 3. Dead code | function never called | NOT_REACHABLE | ✅ | N/A (skipped) |

### Case 2 Internal Trigger Subtypes

| Subtype | Python | JS | Go | Java |
|---------|--------|-----|-----|------|
| Threading | `Thread.start()` | `Worker` | `go func()` | `Thread.start()` |
| Timer | `Timer` | `setInterval` | `time.AfterFunc` | `@Scheduled` |
| Startup | `atexit` | `process.on('exit')` | `init()` | `@PostConstruct` |
| Module-level | `os.system()` | IIFE | `init()` | `static {}` |
| Signal | `signal.signal()` | `process.on('SIGUSR1')` | `signal.Notify` | `addShutdownHook` |
| C2 beacon | Timer → `urlopen(c2)` | `setInterval` → `http.get` | goroutine → `http.Get` | `ScheduledExecutor` |
| Constructor | `Class()` at module level | `new Class()` at module level | N/A | instance init `{}` |

### Test Files

| File | Case | CWEs |
|------|------|------|
| `python/http_endpoint.py` | 1 | CWE-89, 78, 22, 918 |
| `python/internal_trigger.py` | 2 | CWE-89, 78, 200, 918 (7 subtypes) |
| `python/dead_code.py` | 3 | CWE-89, 78, 22, 918, 94 |
| `javascript/http_endpoint.js` | 1 | CWE-89, 78, 22, 918 |
| `javascript/internal_trigger.js` | 2 | CWE-78, 89, 200, 918 (7 subtypes) |
| `javascript/dead_code.js` | 3 | CWE-89, 78, 22, 918, 94 |
| `go/main.go` | 1+2+3 | CWE-89, 78, 22, 200, 918 |
| `java/InvocationPatterns.java` | 1+2+3 | CWE-89, 78, 22, 200, 918 |

See `invocation-patterns/expected-results.json` for the full validation spec and `SIGNAL-INVENTORY.md` for the risk matrix.

---

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

## Reachability Baseline (testbed.json v1.6)

Ground-truth reachability for all signal types, verified from source code analysis.

### Top-level sections

| Section | REACHABLE | NOT_REACHABLE | Total | Rationale |
|---------|:---------:|:-------------:|:-----:|----------|
| CVE | 6 | 2 | 8 | Call graph traces imports from entrypoints to vulnerable packages |
| CWE | 16 | 0 | 16 | All test CWE functions have `@app.route` Flask decorators |
| Secrets | 5 | 1 | 6 | Inline secrets in routed code = reachable; dead-code module = not |
| DLP | 7 | 0 | 7 | DLP scanner treats PII presence as reachable by design |
| AI | 0 | 8 | 8 | Standalone files — no Flask routes, not imported by any entrypoint |
| Malware | 6 | 0 | 6 | Install hooks (`setup.py`, `postinstall`) are reachable by definition |

### Reachability validation (`reachability_validation` — 134 entries, 40 canaries)

| Category | REACHABLE | NOT_REACHABLE | UNKNOWN | Total |
|----------|:---------:|:-------------:|:-------:|:-----:|
| Signal matrix (6 signals × 4 langs) | 23 | 24 | 19 | 66 |
| CWE framework tests (Flask/Django/FastAPI/NestJS/Fastify/Echo) | 23 | 10 | 0 | 33 |
| Framework validation (7 frameworks) | 11 | 11 | 0 | 22 |
| Reachability-states-test | 2 | 2 | 0 | 4 |
| Callgraph canaries (JS/Java) | 1 | 3 | 0 | 4 |
| Client-side app (React) | 1 | 1 | 0 | 2 |
| Transitive deps | 1 | 0 | 0 | 1 |
| Site-packages exclusion | 1 | 0 | 0 | 1 |
| CVE group test | 0 | 1 | 0 | 1 |
| **TOTAL** | **63** | **52** | **19** | **134** |

### SQL injection matrix (`sqli_variable_origin` — 15 entries)

> These are the taint-analysis validation cases. TP cases (user-input → SQL sink) are verified via `reachability_validation` as REACHABLE CWE findings. The 15 entries here focus on taint origin accuracy.

| Category | Count | Expected |
|----------|:-----:|----------|
| False Positives (FP-1..FP-8) | 8 | Detected but should be downgraded (safe variable origin) |
| True Negatives (TN-1..TN-3) | 3 | No finding (parameterized queries) |
| Edge Cases (EDGE-1..EDGE-4) | 4 | Detected as CWE-89 |

### Exclusion validation (`exclusion_validation` — 4 entries)

| Pattern | Expected Findings |
|---------|:-----------------:|
| `.venv/**/site-packages/**` | 0 |
| `venv/**/site-packages/**` | 0 |
| `myenv/**/site-packages/**` | 0 |
| `conda_env/**/site-packages/**` | 0 |

Exclusion targets `site-packages` directly — works regardless of venv directory name.

---

## Test Procedure

Run this procedure before every beta release to confirm zero regressions.

### Step 1 — Full scan

```bash
reachctl scan ~/src/reach-testbed --ai-enhance
```

Expected: exits 0, no `FATAL` or `Traceback` in scan log.

### Step 2 — Run validator

```bash
cd ~/src/reach-testbed
python validate.py --db ~/.reachable/scans/reach-testbed-*/repo.db --verbose
```

The validator checks all assertions in `testbed.json`:
- 8 CVE + 16 CWE + 6 SECRET + 7 DLP + 8 AI + 6 MALWARE detection assertions
- 3 CVE group assertions (Pillow, cryptography, paramiko)
- 134 reachability state assertions (63 REACHABLE, 52 NOT_REACHABLE, 19 UNKNOWN)
- 22 framework validation assertions (11 REACHABLE, 11 NOT_REACHABLE across 7 frameworks)
- 40 canary entries (failure = release blocker)
- 4 site-packages exclusion assertions
- 15 SQL injection variable origin assertions (FP/TN/EDGE taint cases)

### Step 3 — Interpret results

| Output | Meaning | Action |
|--------|---------|--------|
| `PASS` | Assertion met | Nothing |
| `MISS` | Expected finding not found | Bug in detection — file issue |
| `FAIL` | Reachability state wrong | Bug in call graph or pipeline — file issue |
| `WARN` | Expected UNKNOWN got REACHABLE or vice versa | Investigate, may be legit improvement |

**Any FAIL or MISS on a canary entry = release blocker. Do not ship.**

Canary entries are marked `"canary": true` in `testbed.json`. They cover:
- Signal matrix UNKNOWN state (call graph must produce UNKNOWN, not fall back to REACHABLE)
- JS callgraph NOT_REACHABLE canaries (`npm-callgraph-test/`)
- Java callgraph NOT_REACHABLE canary (`java-callgraph-test/`)
- CWE framework-specific canaries (Django, FastAPI, NestJS, Fastify, Echo)
- Client-side React canary

### Step 4 — Check signal counts

Verify scan output counts reconcile with the b35 baseline in the Scan Baseline table above. Unexplained drops in any signal type indicate a pipeline regression.

```bash
reachctl scan ~/src/reach-testbed --summary-only
```

### Step 5 — Run private registry tests (if applicable)

```bash
cd ~/src/reach-testbed/private-registry
./setup-and-test.sh
```

Only required if `reach-core` registry resolution code changed since last release.

### Step 6 — Confirm DLP reachability is not hardcoded

DLP is the highest-risk signal for hardcoded reachability (known b35 bug). After any DLP pipeline change:

```bash
grep -n 'is_reachable' ~/.reachable/scans/reach-testbed-*/dlp-analyzed.json | head -20
```

All DLP findings should have `is_reachable` set from the call graph, not hardcoded to `1`.

---

## Taint Analysis Fixtures (taint-fixtures-v2/)

Standalone fixture files for measuring and improving `taint_intra.py` accuracy. Each fixture is a single-function code snippet with header metadata declaring the expected verdict (TRUE_POSITIVE or TRUE_NEGATIVE).

**Current stats:** 248 fixtures, 9 CWEs, 4 languages, 99.6% engine accuracy.

| CWE | Description | Fixtures |
|-----|-------------|----------|
| CWE-22 | Path Traversal | 34 |
| CWE-78 | Command Injection | 66 |
| CWE-79 | Cross-Site Scripting | 31 |
| CWE-89 | SQL Injection | 46 |
| CWE-94 | Code Injection | 12 |
| CWE-502 | Deserialization | 17 |
| CWE-601 | Open Redirect | 2 |
| CWE-611 | XXE | 7 |
| CWE-918 | SSRF | 13 |

### Running the tests

```bash
cd ~/src/reach-testbed/taint-fixtures-v2

# Structural validation (checks headers, file format, verdict labels)
REACH_CORE=~/src/reach-core python validate_fixtures.py --v2-only --verbose

# Taint engine accuracy (exercises taint_intra.py against each fixture)
REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose

# Save JSON baseline for comparison
REACH_CORE=~/src/reach-core python run_taint_engine.py --json -o accuracy-next.json
```

### Fixture format

Each fixture file has header comments with metadata:

```python
# Fixture: CWE-78 Command Injection - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: subprocess_shell_user_input
# SOURCE: request.args
# SINK: subprocess.run
# TAINT_HOPS: 1
# NOTES: User input passed to subprocess with shell=True
# REAL_WORLD: langchain-ai/langchain ShellTool pattern
```

- `VERDICT` is the ground truth: `TRUE_POSITIVE` means the code IS vulnerable and the engine SHOULD flag it. `TRUE_NEGATIVE` means the code is safe and the engine should NOT flag it.
- `PATTERN` describes the specific coding pattern being tested.
- `REAL_WORLD` links to the repo/file the pattern was mined from.

### Dual-batch architecture

The testbed uses two separate batches:

- **Golden baseline** (`reach-core/enzo/tests/extended/fixtures/`) — 24 fixtures, frozen, blocking for CI. Never modify these.
- **V2 extended** (`reach-testbed/taint-fixtures-v2/`) — 248 fixtures, informational, used for accuracy measurement and improvement. This is where new fixtures go.

### Weekly pattern harvester

New taint patterns are mined weekly from popular open-source repos via GitHub API. The harvester runs as a scheduled Claude task every Monday at 9am.

**Automated harvest workflow:**

```bash
cd ~/src/reach-testbed/taint-fixtures-v2

# 1. Run the harvester (mines 30+ repos across Python/Go/Java/TypeScript)
python harvest_patterns.py

# 2. Review staged candidates
ls staging/
# Check each candidate's VERDICT label, delete bad ones

# 3. Promote approved candidates to the testbed
python harvest_patterns.py --promote

# 4. Regenerate manifest and validate
REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose

# 5. Commit
git add taint-fixtures-v2/ testbed.json
git commit -m "taint-fixtures-v2: add harvested patterns"
```

**What the harvester does:**
1. Searches 30+ repos (django, flask, kubernetes, grafana, elasticsearch, vscode, langchain, ollama, spring-ai, etc.) for known sink patterns
2. Extracts the function containing each match
3. Deduplicates against all existing 248+ fixtures using content signatures
4. Classifies by CWE and guesses TP/TN verdict based on sanitizer presence
5. Writes candidates to `staging/` for human review

**Repos mined (by language):**

- Python: django, flask, requests, langchain, llama_index, autogen, fastapi, airflow, celery
- Go: kubernetes, grafana, ollama, LocalAI, terraform, vault, moby, containerd
- Java: elasticsearch, spring-framework, spring-ai, kafka, flink, langchain4j, keycloak
- TypeScript: vscode, vercel/ai, openai-node, TypeChat, node, nestjs, prisma, trpc

**Options:**
- `--lang python` — harvest only one language
- `--dry-run` — show what would be searched without fetching
- `--max-per-repo 10` — adjust candidates per repo (default 5)
- `--promote` — move reviewed staging candidates into the main testbed

### Key files

| File | Purpose |
|------|---------|
| `validate_fixtures.py` | Structural validation (headers, format, language detection) |
| `run_taint_engine.py` | Exercises actual `taint_intra.py` against each fixture |
| `harvest_patterns.py` | Weekly pattern miner from GitHub repos |
| `manifest.json` | Full fixture inventory with metadata |
| `ACCURACY_REPORT.md` | Detailed accuracy breakdown and failure analysis |
| `TAINT_INTRA_FP_FIXES.md` | Handoff doc for taint engine improvements |
| `accuracy-v4-repo-mined.json` | Latest engine accuracy baseline |

### Adding fixtures manually

1. Create a file in the appropriate `{language}/{cwe}/` directory
2. Use naming convention: `tp_` prefix for true positives, `tn_` prefix for true negatives
3. Add header comments with VERDICT, PATTERN, SOURCE, SINK, TAINT_HOPS
4. Run `python validate_fixtures.py --v2-only` to check structure
5. Run `REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose` to check engine accuracy
6. If the engine gets your fixture wrong, document it in TAINT_INTRA_FP_FIXES.md

---

## Adding New Test Cases

1. Create directory with vulnerable code
2. Document expected CVEs in README
3. Add `expected-results/{name}.json`
4. Add entries to `testbed.json` (detection assertions + reachability assertions)
5. Update this README and SIGNAL-INVENTORY.md counts
6. Update validation workflow

## License

**© 2026 Sthenos Security. All rights reserved.**

Created by Alain Dazzi | info@sthenosec.com
