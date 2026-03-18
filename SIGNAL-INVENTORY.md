# REACHABLE Signal Inventory & Competitor Comparison

> Source of truth: `testbed.json` + test code (reach-testbed @ 2943c74e)  
> Purpose: Pre-release validation baseline + sales/investor comparison tool  
> Rule: This file is derived from test cases. Never edit to match scan output.

---

## Signal Priority Tiers

| Priority | Tier | Rationale |
|----------|------|-----------|
| P0 | CRITICAL blocker | Reachable exploit path, high EPSS, CISA KEV or active exploit |
| P1 | Must fix | Reachable, HIGH severity, or REACHABLE secret/PII |
| P2 | Should fix | REACHABLE MEDIUM, or UNKNOWN (can't rule out path) |
| P3 | Backlog | NOT_REACHABLE — no call path found; deprioritise |
| P4 | Informational | Config/IaC control-plane findings |

---

## Test Case Inventory (from testbed.json)

> Source of truth: `testbed.json` + test code in reach-testbed @ 2943c74e  
> These numbers come from TEST CASES, not scan output. They change only when tests are added or removed.

### Signal Detection Baselines

Expected findings that `validate.py` checks for:

| Signal | Test cases | Source |
|--------|------:|--------|
| CVE | 11 | `testbed.json` → `cve` |
| CWE | 16 | `testbed.json` → `cwe` |
| SECRET | 6 | `testbed.json` → `secrets` |
| DLP | 7 | `testbed.json` → `dlp` |
| AI | 8 | `testbed.json` → `ai` |
| MALWARE | 6 | `testbed.json` → `malware` |
| CVE groups | 4 | `testbed.json` → `cve_groups` (Pillow, cryptography, werkzeug, paramiko) |

### Reachability Assertions (84 total)

Expected reachability states that `validate.py` checks:

| Category | REACHABLE | NOT_REACHABLE | UNKNOWN | Total |
|----------|------:|------:|------:|------:|
| Signal matrix (6 signals × 4 langs) | 23 | 24 | 19 | 66 |
| Reachability-states-test | 2 | 2 | 0 | 4 |
| Transitive deps | 1 | 1 | 0 | 2 |
| Callgraph canaries (JS/Java) | 1 | 3 | 0 | 4 |
| SQLI matrix (TP/FP/EDGE) | 5 | 3 | 0 | 8 |
| **TOTAL** | **32** | **33** | **19** | **84** |

29 of these are **canary** entries — regressions on canaries are release-blockers.

### AI Reachability Design

AI analyzes 4 signal types. CVE/MALWARE/CONFIG are skipped by design.

| Signal | AI analyzes? | What AI asks |
|--------|:---:|------|
| CWE | ✅ | Is the variable attacker-controlled? |
| SECRET | ✅ | Is the key loaded by an SDK? |
| DLP | ✅ | Is PII masked before the sink? |
| AI/LLM | ✅ | Does user input reach LLM without guardrails? |
| CVE | ❌ | Call graph + EPSS/KEV is the gold standard. Fix = upgrade. |
| MALWARE | ❌ | Behavior overrides taint. Remove the package. |
| CONFIG | ❌ | Declarative policy. No code to analyze. |

**Malware guard v2:** Files with malware findings are analyzed normally. AI can
confirm ATTACKER_CONTROLLED (user input reaches shell). Demotion to SAFE is blocked
(behavior overrides taint — `os.system("curl c2")` is SAFE from taint but CRITICAL
from behavior).

---

## Reachability Coverage by Signal

| Signal | Reachability Applied? | Notes |
|--------|-----------------------|-------|
| CVE | ✅ Full (call graph) | Python/JS/Go/Java call graphs; EPSS + KEV enrichment |
| SECRET | ✅ Partial (import graph) | REACHABLE if secret flows into called function; UNKNOWN if module imported but function not traced |
| CWE | ✅ Full (call graph) | SAST findings mapped to call graph |
| DLP | ✅ Full (taint + call graph) | Taint flows from PII source to sink |
| AI | ✅ Full (call graph) | LLM API calls traced from HTTP entrypoints |
| MALWARE | ⚠️ Static only | GuardDog + YARA; no call-path tracing yet |
| IAC/CONFIG | ❌ N/A | Control-plane; reachability not meaningful |
| SANDBOX | ✅ Dynamic | Runtime detonation; REACHABLE if executed in sandbox |

---

## Competitor Coverage Matrix

| Signal | REACHABLE | Snyk | Trivy | Grype | Semgrep | Checkmarx | SonarQube | Endor Labs |
|--------|:---------:|:----:|:-----:|:-----:|:-------:|:---------:|:---------:|:----------:|
| CVE (SCA) | ✅ + reach | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ + reach |
| CVE reachability | ✅ | ⚠️ partial | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| SECRET | ✅ + reach | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| Secret reachability | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CWE / SAST | ✅ + reach | ⚠️ limited | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ |
| CWE reachability | ✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ partial | ❌ | ❌ |
| DLP / PII | ✅ + reach | ❌ | ❌ | ❌ | ⚠️ rules only | ⚠️ rules only | ❌ | ❌ |
| DLP taint tracking | ✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ partial | ❌ | ❌ |
| AI / LLM security | ✅ | ❌ | ❌ | ❌ | ⚠️ rules only | ❌ | ❌ | ❌ |
| AI reachability | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| MALWARE (static) | ✅ | ❌ | ✅ | ⚠️ limited | ❌ | ❌ | ❌ | ⚠️ limited |
| MALWARE (dynamic) | ✅ sandbox | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| IAC / Config | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ⚠️ | ❌ |
| Supply chain (SBOM) | ✅ | ✅ | ✅ | ✅ | ❌ | ⚠️ | ❌ | ✅ |
| EPSS enrichment | ✅ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ✅ |
| CISA KEV | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Multi-signal correlation | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

> ✅ Full support · ⚠️ Partial/limited · ❌ Not supported

---

## Noise Reduction Comparison (CVE only, representative apps)

| Testcase | Language | Raw CVEs | REACHABLE | Noise reduced | Tool comparison |
|----------|----------|--------:|----------:|--------------:|----------------|
| `python-app` | Python | 47 | 3 | **93.6%** | Snyk/Trivy: all 47 flagged |
| `go-app` | Go | 23 | 2 | **91.3%** | Grype: all 23 flagged |
| `javascript-app` | JS | 156 | 9 | **94.2%** | npm audit: 312 flagged |
| `noisy-enterprise-app` | JS | 283 | 11 | **96.1%** | Trivy: 283, Snyk: 267 |
| `reach-testbed` (full) | Multi | 46 | 27 | **41.3%** | *(testbed intentionally noisy)* |

---

## Signal Detection Counts by Language (signal-matrix testbed)

Expected detections when scanning `signal-matrix/`:

| Signal | Python | JS | Go | Java | Total cells |
|--------|-------:|---:|---:|-----:|------------:|
| CVE | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| CWE | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| SECRET | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| DLP | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| AI | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| MALWARE | 2 (R/NR) | 2 (R/NR) | 2 (R/NR) | 1 (NR) | 7 |
| **TOTAL** | **17** | **17** | **17** | **16** | **67** |

R=REACHABLE · NR=NOT_REACHABLE · U=UNKNOWN

A competitor scanning `signal-matrix/` and treating all findings as equally urgent would report
the same raw count but with **zero reachability differentiation** — every REACHABLE, UNKNOWN,
and NOT_REACHABLE finding would be collapsed into a single undifferentiated list.

---

## Severity × Reachability Priority Matrix

Use this to triage scan output:

| Severity | REACHABLE | UNKNOWN | NOT_REACHABLE |
|----------|-----------|---------|---------------|
| **CRITICAL** | 🔴 P0 — fix now | 🟠 P1 — investigate | ⚪ P3 — backlog |
| **HIGH** | 🔴 P0 — fix now | 🟠 P1 — investigate | ⚪ P3 — backlog |
| **MEDIUM** | 🟡 P2 — sprint | 🟡 P2 — sprint | ⚪ P3 — backlog |
| **LOW** | 🟢 P3 — backlog | 🟢 P3 — backlog | ⚪ P4 — ignore |

---

## What Competitors Cannot Do

| Capability | REACHABLE | Any other single tool |
|------------|:---------:|:---------------------:|
| CVE + SECRET + CWE + DLP + AI + MALWARE in one scan | ✅ | ❌ |
| Reachability across ALL signal types | ✅ | ❌ |
| Multi-signal correlation (e.g. CWE + DLP = HIPAA violation) | ✅ | ❌ |
| PII taint tracking to LLM API sinks | ✅ | ❌ |
| Dynamic sandbox + static correlation | ✅ | ❌ |
| Single risk score across all signals | ✅ | ❌ |
| Supply chain package health scoring | ✅ | ❌ |

---

---

## Exclusion Validation

Verifies that REACHABLE does not report findings from third-party library code inside `site-packages`.

| Scenario | Venv name | CWE patterns inside | Expected findings |
|---|---|---|---|
| Standard `.venv` | `.venv` | xmlrpc | 0 |
| Standard `venv` | `venv` | f-string SQL | 0 |
| Non-standard (customer bug) | `myenv` | eval, os.system | 0 |
| Conda-style | `conda_env` | subprocess, pickle | 0 |
| **Real app code** | — | **SQL injection (CWE-89)** | **1+ (REACHABLE)** |

Test directory: `site-packages-test/`

---

## SQL Injection Variable Origin Matrix

Tests whether REACHABLE can distinguish exploitable SQL injection (user-controlled input) from false positives (safe variable origins). All functions are reachable from Flask routes — the test is variable-level taint, not function-level reachability.

Test file: `cwe-tests/python/cwe_sqli_matrix.py`

### True Positives (must detect as REACHABLE)

| ID | Function | Variable origin | Expected |
|---|---|---|---|
| TP-1 | `tp_concat` | `request.args.get('name')` → string concat | REACHABLE |
| TP-2 | `tp_fstring` | `request.args.get('id')` → f-string | REACHABLE |
| TP-3 | `tp_percent` | `request.args.get('cat')` → `%` format | REACHABLE |
| TP-4 | `tp_format` | `request.args.get('table')` → `.format()` | REACHABLE |
| TP-5 | `tp_json_body` | `request.json.get('filter')` → f-string | REACHABLE |
| TP-6 | `tp_indirect` | `request.args` → intermediate var → f-string | REACHABLE |
| TP-7 | `tp_helper` | `request.args` → helper function → concat | REACHABLE |

### False Positives (should be downgraded — variable is safe)

| ID | Function | Variable origin | Expected | Today |
|---|---|---|---|---|
| FP-1 | `fp_constant` | `user_id = 42` | NOT_REACHABLE / LOW | REACHABLE (FP) |
| FP-2 | `fp_config` | `APP_CONFIG["admin_table"]` | NOT_REACHABLE / LOW | REACHABLE (FP) |
| FP-3 | `fp_env` | `os.environ.get("DB_SCHEMA")` | NOT_REACHABLE / LOW | REACHABLE (FP) |
| FP-4 | `fp_int_cast` | `int(request.args.get('id'))` | NOT_REACHABLE / LOW | REACHABLE (FP) |
| FP-5 | `fp_computed` | `len(query_result)` | NOT_REACHABLE / LOW | REACHABLE (FP) |
| FP-6 | `fp_allowlist` | `request.args` validated against set | NOT_REACHABLE / LOW | REACHABLE (FP) |
| FP-7 | `fp_loop` | `range(5)` loop counter | NOT_REACHABLE / LOW | REACHABLE (FP) |
| FP-8 | `fp_internal_fn` | `_get_active_table()` returns constant | NOT_REACHABLE / LOW | REACHABLE (FP) |

### True Negatives (parameterized — should not be flagged at all)

| ID | Function | Pattern | Expected |
|---|---|---|---|
| TN-1 | `tn_param_qmark` | `execute("...?", (val,))` | No finding |
| TN-2 | `tn_param_named` | `execute("...:name", {"name": val})` | No finding |
| TN-3 | `tn_param_dbapi` | `execute("...%s", (val,))` | No finding |

### Edge Cases (complex patterns — must still flag)

| ID | Function | Pattern | Expected |
|---|---|---|---|
| EDGE-1 | `edge_mixed` | Constant + `request.args` in same query | REACHABLE |
| EDGE-2 | `edge_conditional` | One branch safe, one branch unsafe | REACHABLE |
| EDGE-3 | `edge_reassign` | Variable starts safe, overwritten with user input | REACHABLE |
| EDGE-4 | `edge_join` | User-controlled list joined into IN clause | REACHABLE |

> **Note:** FP-1 through FP-8 are expected to be false positives TODAY (reported as REACHABLE). The AI Taint Analysis Oracle (see `enzo/docs/ai-taint-analysis-oracle.md`) is designed to resolve these. This matrix provides the ground truth to measure improvement.

---

## AI Reachability (enzo analyze)

`reachctl scan --ai-enhance` or `reachctl enzo analyze` runs three-layer reachability:
1. **Call graph** (deterministic): Is the FUNCTION reachable?
2. **AI taint oracle**: Is the VARIABLE attacker-controlled?
3. **AI invocation classifier** (planned): HOW does the code execute?

### Cache management

```bash
reachctl enzo analyze ~/src/myapp --clear-cache   # Clear + re-analyze
```

Cache is per-repo, stored in the `ai_reachability_audit` table in `repo.db`.
Same prompt (same code + same finding) = same answer. Cache is invalidated
automatically when code changes (different SHA-256 prompt hash).

---

## Invocation Pattern Test Matrix

Tests the three fundamental ways code can execute. Located in `invocation-patterns/`.

### The Three Cases

| Case | Pattern | Example | Expected State | RA Today | AI Can Help? |
|------|---------|---------|---------------|----------|-------------|
| 1. External endpoint | HTTP route → function → sink | `@app.route → cursor.execute(f"{user_input}")` | REACHABLE | ✅ Detected | ✅ Confirms taint |
| 2. Internal trigger | thread/timer/init → function → sink | `threading.Timer(60, cleanup).start()` | REACHABLE | ❌ **Gap** | ⚠️ Can classify pattern |
| 3. Dead code | function exists, never called | `def vulnerable(x): exec(x)` | NOT_REACHABLE | ✅ Detected | N/A (skipped) |

### Case 2 Subtypes (Internal Triggers)

| Subtype | Python | JavaScript | Go | Java |
|---------|--------|------------|-----|------|
| Threading | `threading.Thread.start()` | `new Worker()` | `go func(){}()` | `new Thread().start()` |
| Timer/scheduled | `threading.Timer`, `sched` | `setInterval`, `setTimeout` | `time.AfterFunc` | `@Scheduled`, `ScheduledExecutorService` |
| Startup/init | `atexit.register()` | `process.on('exit')`, IIFE | `func init()` | `@PostConstruct`, `static {}` |
| Module-level | top-level `os.system()` | top-level `execSync()` | `init()` | static initializer blocks |
| Signal handler | `signal.signal(SIGUSR1, fn)` | `process.on('SIGUSR1')` | `signal.Notify` | `Runtime.addShutdownHook` |
| C2 beacon | Timer → `urlopen("https://c2...")` | `setInterval` → `http.get(c2)` | goroutine → `http.Get(c2)` | `ScheduledExecutor` → `URL.openConnection` |
| Constructor | `AutoInitService()` at module level | `new AutoInitCache()` at module level | N/A (no constructors) | instance initializer `{}` |

### Risk Matrix (Reachable × Tainted × Behavior)

| Reachable | Tainted | Behavior | Classification | Severity |
|-----------|---------|----------|---------------|----------|
| yes (external) | yes | shell exec | **Command Injection** | CRITICAL |
| yes (external) | no | dangerous exec | **Unsafe API use** | HIGH |
| yes (internal) | no | C2 download | **Malware** | CRITICAL |
| yes (internal) | no | normal API call | **Benign internal** | LOW |
| no | no | any | **Dead code** | INFO |

### Test Files

| File | Language | Case | CWEs | Subtypes |
|------|----------|------|------|----------|
| `python/http_endpoint.py` | Python | 1 | CWE-89, 78, 22, 918 | Flask routes |
| `python/internal_trigger.py` | Python | 2 | CWE-89, 78, 200, 918 | Thread, Timer, atexit, signal, module-level, C2, __init__ |
| `python/dead_code.py` | Python | 3 | CWE-89, 78, 22, 918, 94 | Never called |
| `javascript/http_endpoint.js` | JS | 1 | CWE-89, 78, 22, 918 | Express routes |
| `javascript/internal_trigger.js` | JS | 2 | CWE-78, 89, 200, 918 | setInterval, setTimeout, process.on, IIFE, C2, constructor |
| `javascript/dead_code.js` | JS | 3 | CWE-89, 78, 22, 918, 94 | Never required |
| `go/main.go` | Go | 1+2+3 | CWE-89, 78, 22, 200, 918 | gin routes + init()/goroutines + dead exports |
| `java/InvocationPatterns.java` | Java | 1+2+3 | CWE-89, 78, 22, 200, 918 | @PostMapping + @PostConstruct/@Scheduled/static{} + dead methods |

### Known Gaps (RA entrypoint detection)

The call graph currently only traces from these entrypoints:

| Language | Detected Entrypoints | Missing (Case 2) |
|----------|---------------------|------------------|
| Python | `@app.route`, `main()`, `if __name__` | `threading.Thread/Timer.start()`, `atexit.register()`, `signal.signal()`, module-level calls |
| JavaScript | `app.get/post`, `module.exports` called from server | `setInterval/setTimeout`, `process.on()`, IIFE, module-level calls |
| Go | `func main()`, `r.GET/POST` | `func init()`, `go func(){}()`, `signal.Notify` |
| Java | `@GetMapping/@PostMapping`, `public static void main` | `@PostConstruct`, `@Scheduled`, `static {}`, `addShutdownHook` |

Fixing these gaps requires changes to the deterministic call graph in reach-core (other session).
The AI behavioral classifier (Phase 3) can partially compensate by reading code patterns.

### Known Bugs

Tracked in **reach-core** → `docs/data_quality_b35_bugs.md` (11 bugs, 6 root causes).
All are reach-core fixes — CG engine, DLP pipeline, schema migrations.

**AI verdicts are correct on everything the CG gives them.** These are CG-layer and schema
issues, not AI issues. All REACHABLE findings get accurate ATTACKER_CONTROLLED / SAFE /
UNCERTAIN verdicts.

---

## Pre-Release Validation

Run `validate.py` before every beta/release build:

```bash
reachctl scan ~/src/reach-testbed --ai-enhance
cd ~/src/reach-testbed
python validate.py --db ~/.reachable/scans/reach-testbed-*/repo.db --verbose
```

The validator checks (from `testbed.json`):
- 11 CVE + 16 CWE + 6 SECRET + 7 DLP + 8 AI + 6 MALWARE detection assertions
- 84 reachability state assertions (32 REACHABLE, 33 NOT_REACHABLE, 19 UNKNOWN)
- 29 canary entries (regressions on canaries are release-blockers)
- 4 exclusion assertions (site-packages must not be scanned)
- 15 SQL injection variable origin assertions

Any NEW failure = regression. Do not ship.

---

*Last updated: 2026-03-15 · Source of truth: testbed.json @ reach-testbed 2943c74e*
