# REACHABLE Signal Inventory & Competitor Comparison

> Reference: `expected-results/full-scan-v5.1.3.json` (reach-testbed @ 2943c74e)  
> Purpose: Pre-release validation baseline + sales/investor comparison tool

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

## Signal Inventory (reach-testbed full scan baseline)

> Baseline: v1.0.0b34 · scan date: 2026-03-15 · `--ai-enhance` enabled · malware guard v2

| Signal | Total | Exploitable | Unverified | Filtered | Config | Priority |
|--------|------:|------------:|-----------:|---------:|-------:|----------|
| **CVE** | 103 | 60 | 0 | 43 | — | P0–P1 |
| **CWE** | 458 | 102 | 114 | 242 | — | P1–P2 |
| **SECRET** | 112 | 21 | 15 | 76 | — | P0–P1 |
| **DLP** | 67 | 67 | 0 | 0 | — | P0–P1 |
| **AI** | 183 | 52 | 0 | 131 | — | P1–P2 |
| **MALWARE** | 343 | 97 | 0 | 246 | — | P0 |
| **CONFIG** | 169 | — | — | — | 134 | P4 |
| **TOTAL** | **1435** | **399** | **129** | **738** | **134** | — |

> **Noise reduction: 56.4%** — 399 exploitable + 129 unverified out of 1435 total.  
> 683 findings filtered by reachability analysis. CONFIG findings excluded from noise funnel.

### AI Reachability (enzo analyze, groq/llama-3.3-70b)

| Metric | Count | Notes |
|--------|------:|-------|
| Findings analyzed | 419 | CWE + SECRET + DLP + AI/LLM (CVE/MALWARE/CONFIG skipped by design) |
| Confirmed exploitable | 171 | Attacker-controlled input reaches the sink |
| Downgraded (safe) | 50 | Constant, config value, int-cast, or validated input |
| Cache hits | 58 | Unchanged code skipped (prompt-hash match) |

**Per-signal AI breakdown:**

| Signal | Exploitable | Safe | Total | What AI asks |
|--------|------:|------:|------:|------|
| CWE (taint) | 56 | 17 | 233 | Is the variable attacker-controlled? |
| SECRET (loader) | 12 | 33 | 67 | Is the key loaded by an SDK? |
| DLP (flow) | 67 | 0 | 67 | Is PII masked before the sink? |
| AI/LLM | 36 | 0 | 52 | Does user input reach LLM without guardrails? |

**Signals NOT analyzed by AI (by design):**

| Signal | Why skipped |
|--------|-------------|
| CVE | Call graph + EPSS/KEV is the gold standard. Fix = upgrade. |
| MALWARE | Behavior overrides taint. Remove the package, not check the variable. |
| CONFIG | Declarative policy. No function, no variable, no code to analyze. |

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
| CWE | ✅ Full (call graph) | SAST findings mapped to call graph; 261/262 currently NOT_REACHABLE in testbed |
| DLP | ✅ Full (taint + call graph) | All 33 findings REACHABLE in testbed (taint flows to sinks) |
| AI | ✅ Full (call graph) | LLM API calls traced from HTTP entrypoints |
| MALWARE | ⚠️ Static only | GuardDog + YARA; no call-path tracing yet; all UNKNOWN |
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

## AI Reachability Results (enzo analyze)

`reachctl scan --ai-enhance` or `reachctl enzo analyze` runs three-layer reachability:
1. **Call graph** (deterministic): Is the FUNCTION reachable?
2. **AI taint oracle**: Is the VARIABLE attacker-controlled?
3. **AI invocation classifier** (planned): HOW does the code execute?

### Full scan results (v1.0.0b34, groq/llama-3.3-70b)

| Metric | Count | Notes |
|---|---|---|
| Total analyzed | 419 | CWE + SECRET + DLP + AI/LLM |
| Confirmed exploitable | 171 | CWE: 56, SECRET: 12, DLP: 67, AI/LLM: 36 |
| Downgraded (safe) | 50 | CWE: 17, SECRET: 33 |
| Cache hits | 58 | Prompt-hash match — unchanged code skipped |

### Per-signal breakdown

| Signal | Exploitable | Safe | Total | Analysis |
|--------|------:|------:|------:|----------|
| CWE | 56 | 17 | 233 | Taint: is the variable attacker-controlled? |
| SECRET | 12 | 33 | 67 | Loader: is the key used by an SDK? |
| DLP | 67 | 0 | 67 | Flow: is PII masked before the sink? |
| AI/LLM | 36 | 0 | 52 | Guardrails: does user input reach LLM unfiltered? |

### Cache management

```bash
reachctl enzo analyze ~/src/myapp --clear-cache   # Clear + re-analyze
```

Cache is per-repo, stored in the `ai_reachability_audit` table in `repo.db`.
Same prompt (same code + same finding) = same answer. Cache is invalidated
automatically when code changes (different SHA-256 prompt hash).

Malware guard v2: findings in files flagged by the malware scanner are analyzed normally.
Promotion to ATTACKER_CONTROLLED is allowed (confirms real exploitability). Demotion to
SAFE is blocked (behavior overrides taint — C2 download with constant URL is SAFE from
taint perspective but CRITICAL from behavior perspective).

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

---

*Last updated: 2026-03-15 · Baseline: reach-testbed @ 2943c74e · v1.0.0b34 · `--ai-enhance` enabled · malware guard v2*
