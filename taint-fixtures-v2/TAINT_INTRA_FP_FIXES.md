# taint_intra.py — 13 Failures (12 FP + 1 FN)

**Source:** reach-testbed taint engine accuracy run (2026-04-09)
**Current accuracy:** 93.9% (199/212), 99% sensitivity, 89% specificity
**File to modify:** `reach-core/reachable/v2/src/taint_intra.py`
**Fixtures:** 232 total in `~/src/reach-testbed/taint-fixtures-v2/`

## How to reproduce

```bash
cd ~/src/reach-testbed/taint-fixtures-v2
REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose
```

---

## PRIORITY 1: Infra Context Over-Suppression (1 FN — CRITICAL)

**This is the only false negative — a missed vulnerability. Fix first.**

**Fixture:**
- `typescript/cwe78/tp_2hop_config_exec.ts` — Express route handler `runBuild(req, res)` takes `req.body`, destructures `{ repo, branch }`, and passes them to `exec()`. The engine incorrectly suppressed this as infrastructure code because the function name contains "build".

**Root cause:** `_is_infra_context()` matches on function/file name patterns like "build", "deploy", "ci" and marks the signal as NOT_REACHABLE. But this function is a web endpoint that receives user input.

**Fix:** In `_is_infra_context()`, add an override: if the function signature includes HTTP request parameters (e.g., `req`, `request`, `Request`, `HttpServletRequest`, `http.Request`, `flask.request`), do NOT suppress. Web handler functions should never be classified as infra context regardless of their name.

**Verification:** After fix, `tp_2hop_config_exec.ts` should show `suppressed=False, exploitable=True`.

---

## PRIORITY 2: Allowlist Guard Detection (3 FPs)

**Fixtures that should pass after this fix:**
- `go/cwe78/tn_exec_command_allowlist.go` — checks `allowedTools` map before `exec.Command`
- `go/cwe89/tn_allowlist_order_by.go` — checks `allowedColumns` set before SQL interpolation
- `python/cwe78/tn_subprocess_allowlist_guard.py` — checks `ALLOWED_TOOLS` set before `subprocess.run`

**What to do:** In `_has_sanitizer()`, add a heuristic that detects allowlist validation patterns before the sink:
- `if X not in ALLOWED_SET` / `if X not in ALLOWED_MAP` followed by raise/return before sink
- `switch`/`case` exhaustive dispatch (Go)
- `TOOLS[tool_name]` style dict dispatch where the dict is a local constant

The key signal: a conditional guard between source and sink that restricts the value to a finite set of known-safe options.

---

## PRIORITY 3: XSS Framework Sanitizer Recognition (3 FPs — NEW)

**Fixtures that should pass after this fix:**
- `python/cwe79/tn_flask_render_template_autoescape.py` — `render_template()` uses Jinja2 auto-escaping
- `python/cwe79/tn_markupsafe_escape.py` — `markupsafe.escape()` sanitizes before HTML concatenation
- `python/cwe79/tn_django_template_autoescape.py` — Django `TemplateResponse` auto-escapes

**What to do:** Add CWE-79 specific sanitizer functions to `_has_sanitizer()`:

Python:
- `render_template(...)` (note: `render_template_string` is NOT safe — only `render_template`)
- `markupsafe.escape()` / `Markup.escape()`
- `html.escape()`
- `django.utils.html.escape()`

Java:
- `Encode.forHtml()` (OWASP Java Encoder)
- Thymeleaf `th:text` (vs `th:utext` which is unsafe)

TypeScript:
- `DOMPurify.sanitize()` (already handled?)
- `.textContent` assignment vs `.innerHTML`

Important: `render_template_string()` is NOT a sanitizer — it renders a user-controlled template, which is actually SSTI. Only `render_template()` with a filename is safe.

---

## PRIORITY 4: Path Validation Sanitizers for CWE-22 (3 FPs)

**Fixtures that should pass after this fix:**
- `go/cwe22/tn_path_clean_and_check.go` — `filepath.Clean()` + `strings.HasPrefix(resolved, baseDir)`
- `java/cwe22/TnCanonicalPathCheck.java` — `getCanonicalPath()` + `startsWith(BASE_DIR)`
- `python/cwe22/tn_realpath_check.py` — `os.path.realpath()` + `.startswith(UPLOAD_DIR)`

**What to do:** Add CWE-22 specific sanitizer recognition. Pattern is always: path canonicalization + prefix check.

- Python: `os.path.realpath(X)` or `Path(X).resolve()` followed by `.startswith(base)`
- Go: `filepath.Clean(X)` or `filepath.Abs(X)` followed by `strings.HasPrefix(resolved, base)`
- Java: `new File(X).getCanonicalPath()` followed by `.startsWith(baseDir)`

---

## PRIORITY 5: Java Array-Form Exec (1 FP)

**Fixture:** `java/cwe78/TnRuntimeExecArrayNoShell.java` — `Runtime.exec(new String[]{"grep", "-r", pattern, dir})`

**Fix:** Extend existing Go `exec.Command` array-form recognition to Java:
- `Runtime.getRuntime().exec(String[])` — array form, no shell
- `new ProcessBuilder(List)` without `"sh", "-c"` or `"bash", "-c"` — no shell

---

## PRIORITY 6: Config-Sourced Input (1 FP)

**Fixture:** `java/cwe78/TnRuntimeExecConfigSourced.java` — `System.getProperty("tool.path")`

**Fix:** Classify as non-user-controlled sources:
- Java: `System.getProperty(...)`, `System.getenv(...)`
- Python: `os.environ.get(...)`, `os.getenv(...)`
- Go: `os.Getenv(...)`
- TypeScript: `process.env.X`

---

## PRIORITY 7: Literal Suffix in path.join (1 FP)

**Fixture:** `typescript/cwe22/tn_path_join_literal_segments.ts` — `path.join(extensionsPath, 'package.json')` with literal filename.

**Fix:** When `path.join()` has a variable base but ALL subsequent segments are string literals, the attacker cannot control the filename portion.

---

## Verification

After making changes, run:
```bash
cd ~/src/reach-testbed/taint-fixtures-v2
REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose --json -o accuracy-after-fixes.json
```

Target: 100% accuracy (212/212), 0 FPs, 0 FNs.

Make sure the 103 existing true positives still pass — no regressions.
