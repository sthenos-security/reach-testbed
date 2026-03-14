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

| Signal | Total | REACHABLE | NOT_REACHABLE | UNKNOWN | CRIT | HIGH | MED | LOW | Priority |
|--------|------:|----------:|--------------:|--------:|-----:|-----:|----:|----:|----------|
| **CVE** | 46 | 27 | 19 | 0 | 3 | 16 | 25 | 2 | P0–P1 |
| **SECRET** | 119 | 36 | 0 | 83 | 61 | 30 | 28 | 0 | P0–P1 |
| **CWE** | 262 | 1 | 261 | 0 | 90 | 0 | 153 | 19 | P1–P2 |
| **DLP** | 33 | 33 | 0 | 0 | 7 | 10 | 16 | 0 | P0–P1 |
| **AI** | 129 | 86 | 43 | 0 | 0 | 0 | 129 | 0 | P1–P2 |
| **MALWARE** | 19 | 0 | 0 | 19 | 11 | 8 | 0 | 0 | P0 |
| **IAC/CONFIG** | 4 | 0 | 0 | 4 | 0 | 2 | 1 | 1 | P4 |
| **SANDBOX** | 0 | — | — | — | — | — | — | — | P0 (when triggered) |
| **TOTAL** | **612** | **183** | **323** | **106** | **172** | **66** | **352** | **22** | — |

> **Noise reduction: 54.7%** — 183 REACHABLE out of 612 total findings.  
> Excludes IAC/CONFIG from noise funnel (control-plane, not app execution path).

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

*Last updated: 2026-03-13 · Baseline: reach-testbed · v1.0.0b33*
