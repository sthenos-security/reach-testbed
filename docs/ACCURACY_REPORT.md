# Taint Fixtures V2 — Accuracy Report

**Date:** 2026-04-09
**Engine:** taint_intra.py (reach-core @ 64a3efe)
**Fixtures:** 248 total, 228 tested (20 skipped — real_world + inter_procedural)

## Results

| Metric | Value |
|--------|-------|
| **Overall Accuracy** | **99.6%** (227/228) |
| **Sensitivity (TPR)** | **99.1%** (115/116 — 1 false negative) |
| **Specificity (TNR)** | **100%** (112/112 — 0 false positives) |
| **False Positive Rate** | **0%** |
| **False Negative Rate** | **0.9%** (1/116 TPs missed) |

## Evolution

| Run | Fixtures | Tested | Accuracy | FPs | FNs | Engine |
|-----|----------|--------|----------|-----|-----|--------|
| v2 baseline | 168 | 148 | 93.9% | 9 | 0 | pre-Fleet-sprint |
| + AI/LLM | 195 | 175 | 94.9% | 9 | 0 | pre-Fleet-sprint |
| + gap-fill | 232 | 212 | 93.9% | 12 | 1 | pre-Fleet-sprint |
| + repo-mined (current) | 248 | 228 | **99.6%** | 0 | 1 | 64a3efe (Fleet FP sprint) |

The jump from 93.9% to 99.6% is due to the Fleet FP reduction sprint in reach-core (commit 64a3efe) which added allowlist guard detection, path validation sanitizers, array-form exec recognition, and config-source classification. All 12 previous FPs are now correctly handled.

## Per-CWE Breakdown

| CWE | Pass | Fail | Accuracy |
|-----|------|------|----------|
| CWE-22 (Path Traversal) | 33 | 1 | 97% |
| CWE-78 (Command Injection) | 66 | 0 | 100% |
| CWE-79 (Cross-Site Scripting) | 31 | 0 | 100% |
| CWE-89 (SQL Injection) | 46 | 0 | 100% |
| CWE-94 (Code Injection) | 12 | 0 | 100% |
| CWE-502 (Deserialization) | 17 | 0 | 100% |
| CWE-601 (Open Redirect) | 2 | 0 | 100% |
| CWE-611 (XXE) | 7 | 0 | 100% |
| CWE-918 (SSRF) | 13 | 0 | 100% |

## Per-Language Breakdown

| Language | Pass | Fail | Accuracy |
|----------|------|------|----------|
| Go | 42 | 0 | 100% |
| Java | 49 | 0 | 100% |
| TypeScript/JS | 58 | 0 | 100% |
| Python | 78 | 1 | 99% |

## 1 Remaining Failure

### Infra Context Over-Suppression (1 FN)

- `python/cwe22/tp_dataset_id_path.py` — Function `load_dataset_cache(dataset_id)` uses `os.path.join('/home/datasets', dataset_id, 'cache.pkl')` with unvalidated `dataset_id`. The engine incorrectly suppresses this as infrastructure/cache code based on the function name containing "cache" and/or "dataset".

**Fix:** The `_is_infra_context()` heuristic should not suppress functions where the parameter is used in a path construction without validation, regardless of function name.

## Coverage Summary

248 fixtures across 4 languages and 9 CWEs:

| Category | Count |
|----------|-------|
| Command Injection (CWE-78) | 66 |
| SQL Injection (CWE-89) | 46 |
| Path Traversal (CWE-22) | 34 |
| Cross-Site Scripting (CWE-79) | 31 |
| Deserialization (CWE-502) | 17 |
| SSRF (CWE-918) | 13 |
| Code Injection (CWE-94) | 12 |
| XXE (CWE-611) | 7 |
| Open Redirect (CWE-601) | 2 |
| Real-world (Fleet) | 12 |
| Inter-procedural | 8 |
| Multi-hop patterns | 4 |

## Real-World Sources

Patterns mined from 20+ repos:
- microsoft/vscode (OAuth path traversal, template XSS, incomplete quoting, IPC injection)
- elastic/elasticsearch (SSRF redirect following, URL blob name, StAX XXE, cmd.exe /C)
- tensorflow/tensorflow (subprocess, pickle, yaml, path patterns)
- langchain-ai/langchain, microsoft/autogen, run-llama/llama_index (AI agent patterns)
- ollama/ollama, go-skynet/LocalAI (Go AI server patterns)
- spring-projects/spring-ai, langchain4j (Java AI patterns)
- vercel/ai, openai/openai-node, microsoft/TypeChat (TS AI patterns)
- django/django (mark_safe XSS, extra() SQLi, redirect)
- pallets/flask (send_file traversal, redirect)
- grafana/grafana, kubernetes/kubernetes (Go patterns)

## Running

```bash
cd ~/src/reach-testbed/taint-fixtures-v2

# Structural validation (all 248 pass)
REACH_CORE=~/src/reach-core python validate_fixtures.py --v2-only --verbose

# Taint engine accuracy
REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose

# Save JSON baseline
REACH_CORE=~/src/reach-core python run_taint_engine.py --json -o accuracy-next.json
```

## Baselines

- `accuracy-baseline.json` — first run (168 fixtures, 93.9%)
- `accuracy-v2-with-ai.json` — AI/LLM fixtures (195, 94.9%)
- `accuracy-v3-full-coverage.json` — gap-fill (232, 93.9%)
- `accuracy-v4-repo-mined.json` — current (248, 99.6%)
