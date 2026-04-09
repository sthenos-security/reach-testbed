# Taint Fixtures V2 — Accuracy Report

**Date:** 2026-04-09
**Engine:** taint_intra.py (reach-core)
**Fixtures:** 232 total, 212 tested (20 skipped — real_world + inter_procedural)

## Results

| Metric | Value |
|--------|-------|
| **Overall Accuracy** | **93.9%** (199/212) |
| **Sensitivity (TPR)** | **99.0%** (103/104 — 1 false negative) |
| **Specificity (TNR)** | **88.9%** (96/108 — 12 false positives) |
| **False Positive Rate** | **11.1%** (12/108 TNs incorrectly flagged) |
| **False Negative Rate** | **1.0%** (1/104 TPs missed) |

## Evolution

| Run | Fixtures | Tested | Accuracy | FPs | FNs |
|-----|----------|--------|----------|-----|-----|
| v2 baseline | 168 | 148 | 93.9% | 9 | 0 |
| + AI/LLM | 195 | 175 | 94.9% | 9 | 0 |
| + gap-fill (current) | 232 | 212 | 93.9% | 12 | 1 |

The accuracy dip from 94.9% to 93.9% is expected — we added harder tests that expose real engine gaps (XSS sanitizers, multi-hop destructuring).

## Per-CWE Breakdown

| CWE | Pass | Fail | Accuracy |
|-----|------|------|----------|
| CWE-22 (Path Traversal) | 27 | 4 | 87% |
| CWE-78 (Command Injection) | 59 | 5 | 92% |
| CWE-79 (Cross-Site Scripting) | 23 | 3 | 88% |
| CWE-89 (SQL Injection) | 45 | 1 | 98% |
| CWE-94 (Code Injection) | 11 | 0 | 100% |
| CWE-502 (Deserialization) | 17 | 0 | 100% |
| CWE-611 (XXE) | 6 | 0 | 100% |
| CWE-918 (SSRF) | 11 | 0 | 100% |

## Per-Language Breakdown

| Language | Pass | Fail | Accuracy |
|----------|------|------|----------|
| Go | 38 | 3 | 93% |
| Java | 42 | 3 | 93% |
| TypeScript/JS | 51 | 2 | 96% |
| Python | 68 | 5 | 93% |

## 13 Failures — Root Causes

### Category 1: Allowlist/Guard Patterns (3 FPs — original)

The taint engine doesn't recognize allowlist validation before sink usage.

- `go/cwe78/tn_exec_command_allowlist.go` — `allowedTools` map check before `exec.Command`
- `go/cwe89/tn_allowlist_order_by.go` — `allowedColumns` set check before SQL interpolation
- `python/cwe78/tn_subprocess_allowlist_guard.py` — `ALLOWED_TOOLS` check before `subprocess.run`

**Fix:** Allowlist-detection heuristic in `_has_sanitizer()` — `if X not in ALLOWED` or dict/set membership before sink.

### Category 2: Path Validation Patterns (3 FPs — original)

The engine misses `realpath`/`canonicalPath` + `startsWith` as a valid sanitizer for CWE-22.

- `go/cwe22/tn_path_clean_and_check.go` — `filepath.Clean` + `strings.HasPrefix`
- `java/cwe22/TnCanonicalPathCheck.java` — `getCanonicalPath()` + `startsWith(BASE_DIR)`
- `python/cwe22/tn_realpath_check.py` — `os.path.realpath` + `.startswith(UPLOAD_DIR)`

**Fix:** CWE-22 sanitizer patterns: canonicalization + prefix check.

### Category 3: Array-Form Exec (1 FP — original)

- `java/cwe78/TnRuntimeExecArrayNoShell.java` — `Runtime.exec(String[])` array form

**Fix:** Extend Go's `exec.Command` array-form recognition to Java.

### Category 4: Config-Sourced Input (1 FP — original)

- `java/cwe78/TnRuntimeExecConfigSourced.java` — `System.getProperty("tool.path")`

**Fix:** `System.getProperty`/`getenv` as non-user-controlled sources.

### Category 5: Literal Suffix in path.join (1 FP — original)

- `typescript/cwe22/tn_path_join_literal_segments.ts` — literal `'package.json'` suffix

**Fix:** Detect all-literal segments after variable base in `path.join`.

### Category 6: XSS Framework Sanitizer Recognition (3 FPs — NEW)

The engine doesn't recognize framework-level auto-escaping or sanitizer libraries for CWE-79.

- `python/cwe79/tn_flask_render_template_autoescape.py` — `render_template()` uses Jinja2 auto-escaping
- `python/cwe79/tn_markupsafe_escape.py` — `markupsafe.escape()` before HTML concatenation
- `python/cwe79/tn_django_template_autoescape.py` — Django `TemplateResponse` auto-escapes

**Fix:** Add CWE-79 sanitizer recognition:
- Python: `render_template()` (not `render_template_string`), `markupsafe.escape()`, `html.escape()`
- Java: `Encode.forHtml()` (OWASP), Thymeleaf `th:text`
- TypeScript: `DOMPurify.sanitize()`, `textContent` (already handled)

### Category 7: Infrastructure Context Over-Suppression (1 FN — NEW, CRITICAL)

- `typescript/cwe78/tp_2hop_config_exec.ts` — Function named `runBuild` incorrectly suppressed by `_is_infra_context()`. The function is an Express route handler that takes `req.body` user input and passes it to `exec()`. The "build" in the name triggered a false infra classification.

**Fix:** `_is_infra_context()` should not suppress functions that receive HTTP request objects (`req`, `request`, `Request`). Framework entry points should override infra-name heuristics. This is higher priority than FP fixes because it causes a **missed vulnerability**.

## Enhancement Roadmap (Priority Order)

1. **Infra context over-suppression** (1 FN) — CRITICAL: causes missed vulnerabilities. Don't suppress when function takes HTTP request params.
2. **Allowlist guard detection** (3 FPs) — highest FP impact, cross-language
3. **XSS framework sanitizers** (3 FPs) — `render_template`, `escape()`, OWASP Encoder
4. **Path validation sanitizers** (3 FPs) — `realpath/canonical + startsWith`
5. **Java array-form exec** (1 FP) — extend Go pattern to Java
6. **Config source classification** (1 FP) — `System.getProperty/getenv`
7. **Literal suffix in path.join** (1 FP) — narrow TypeScript pattern

## Coverage Summary

232 fixtures across 4 languages and 8 CWEs:

| Category | Count |
|----------|-------|
| AI/LLM framework patterns | 27 |
| XSS (CWE-79) | 26 |
| Command Injection (CWE-78) | 64 |
| SQL Injection (CWE-89) | 46 |
| Path Traversal (CWE-22) | 31 |
| Deserialization (CWE-502) | 17 |
| SSRF (CWE-918) | 11 |
| Code Injection (CWE-94) | 11 |
| XXE (CWE-611) | 6 |
| Real-world (Fleet) | 12 |
| Inter-procedural | 8 |
| Multi-hop patterns | 4 |

## Running

```bash
cd ~/src/reach-testbed/taint-fixtures-v2

# Structural validation
REACH_CORE=~/src/reach-core python validate_fixtures.py --v2-only --verbose

# Taint engine accuracy
REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose

# Save JSON baseline
REACH_CORE=~/src/reach-core python run_taint_engine.py --json -o accuracy-next.json
```

## Baselines

- `accuracy-baseline.json` — first run (168 fixtures)
- `accuracy-v2-with-ai.json` — after AI/LLM fixtures (195)
- `accuracy-v3-full-coverage.json` — current (232 fixtures)
