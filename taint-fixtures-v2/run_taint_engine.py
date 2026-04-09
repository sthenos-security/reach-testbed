#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
run_taint_engine.py — Exercise taint_intra against every v2 fixture
===================================================================

Creates an in-memory DB per fixture, writes the fixture source to a temp dir,
inserts a synthetic signal + function row, then calls run_taint_intra().

Checks whether the signal was suppressed (TN expected) or left as-is / marked
exploitable (TP expected).

Requires: REACH_CORE env var or ../reach-core sibling.

Usage:
    REACH_CORE=~/src/reach-core python run_taint_engine.py
    REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose
    REACH_CORE=~/src/reach-core python run_taint_engine.py --json -o results.json
    REACH_CORE=~/src/reach-core python run_taint_engine.py --lang python --cwe cwe78
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

# ── Locate reach-core taint engine ──────────────────────────────────────────
def _find_reach_core() -> Path:
    env = os.environ.get("REACH_CORE")
    if env:
        p = Path(env)
        if (p / "reachable" / "v2" / "src" / "taint_intra.py").exists():
            return p
    sibling = Path(__file__).resolve().parent.parent / "reach-core"
    if (sibling / "reachable" / "v2" / "src" / "taint_intra.py").exists():
        return sibling
    print("ERROR: Cannot find reach-core. Set REACH_CORE env var.", file=sys.stderr)
    sys.exit(3)

REACH_CORE = _find_reach_core()
TAINT_SRC = REACH_CORE / "reachable" / "v2" / "src"
if str(TAINT_SRC) not in sys.path:
    sys.path.insert(0, str(TAINT_SRC))

from taint_intra import run_taint_intra  # noqa: E402

# ── DB schema (matches test_taint_abcd.py) ──────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    signal_type TEXT NOT NULL DEFAULT 'cwe',
    finding_id TEXT,
    display_id TEXT,
    file_id INTEGER,
    file_path TEXT,
    line_number INTEGER DEFAULT 0,
    severity TEXT DEFAULT 'HIGH',
    title TEXT,
    description TEXT,
    app_reachability TEXT DEFAULT 'UNKNOWN',
    reachability_reason TEXT,
    reachability_confidence TEXT DEFAULT 'LOW',
    cwe_id TEXT,
    package_name TEXT,
    package_version TEXT,
    cvss_score REAL,
    raw_data TEXT,
    containing_function TEXT,
    function_id INTEGER,
    is_final INTEGER NOT NULL DEFAULT 0,
    taint_source TEXT,
    taint_confidence TEXT,
    taint_phase TEXT,
    finalized_by TEXT,
    hints TEXT
);
CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    qname TEXT NOT NULL,
    short_name TEXT NOT NULL,
    file_path TEXT,
    line_number INTEGER DEFAULT 0,
    end_line INTEGER DEFAULT 0,
    language TEXT,
    is_reachable INTEGER DEFAULT 0,
    is_entrypoint INTEGER DEFAULT 0,
    has_user_input INTEGER DEFAULT 0,
    rel_path TEXT
);
CREATE TABLE IF NOT EXISTS call_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    caller TEXT NOT NULL,
    callee TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS taint_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    signal_id INTEGER NOT NULL,
    source_fn TEXT NOT NULL,
    source_line INTEGER,
    source_expr TEXT,
    source_type TEXT NOT NULL,
    sink_fn TEXT NOT NULL,
    sink_line INTEGER,
    sink_param TEXT,
    sink_type TEXT NOT NULL,
    path_json TEXT,
    hop_count INTEGER NOT NULL DEFAULT 0,
    sanitizers TEXT,
    confidence TEXT NOT NULL DEFAULT 'HIGH'
);
"""

# ── Fixture header parsers ──────────────────────────────────────────────────
HEADER_RE = {
    "verdict": re.compile(r"[#/]+\s*VERDICT:\s*(\S+)", re.IGNORECASE),
    "pattern": re.compile(r"[#/]+\s*PATTERN:\s*(.+)", re.IGNORECASE),
    "source": re.compile(r"[#/]+\s*SOURCE:\s*(.+)", re.IGNORECASE),
    "sink": re.compile(r"[#/]+\s*SINK:\s*(.+)", re.IGNORECASE),
    "taint_hops": re.compile(r"[#/]+\s*TAINT_HOPS:\s*(\d+)", re.IGNORECASE),
}

LANG_MAP = {".py": "python", ".go": "go", ".java": "java", ".ts": "javascript", ".js": "javascript"}

# CWE from directory name
def _cwe_from_path(p: Path) -> str:
    for part in p.parts:
        if part.startswith("cwe"):
            return "CWE-" + part[3:]
    return ""

# Find the first function/method name in the fixture
def _find_function_name(source: str, lang: str) -> str:
    patterns = {
        "python": re.compile(r"^\s*def\s+(\w+)\s*\(", re.MULTILINE),
        "go": re.compile(r"^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(", re.MULTILINE),
        "java": re.compile(r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(", re.MULTILINE),
        "javascript": re.compile(r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(", re.MULTILINE),
    }
    rx = patterns.get(lang)
    if not rx:
        return "handler"
    m = rx.search(source)
    if m:
        return m.group(1) or (m.group(2) if m.lastindex >= 2 else None) or "handler"
    return "handler"


def _count_lines(source: str) -> int:
    return source.count("\n") + 1


def run_one_fixture(fixture_path: Path, verbose: bool = False) -> dict:
    """Run taint_intra on a single fixture. Returns result dict."""
    ext = fixture_path.suffix
    lang = LANG_MAP.get(ext)
    if not lang:
        return {"status": "skip", "reason": f"unsupported extension: {ext}"}

    source = fixture_path.read_text(encoding="utf-8", errors="replace")
    head = source[:1000]

    # Parse headers
    meta = {}
    for key, rx in HEADER_RE.items():
        m = rx.search(head)
        if m:
            meta[key] = m.group(1).strip()

    verdict = meta.get("verdict", "UNKNOWN").upper()
    if verdict not in ("TRUE_POSITIVE", "TRUE_NEGATIVE"):
        return {"status": "skip", "reason": f"unknown verdict: {verdict}"}

    cwe = _cwe_from_path(fixture_path)
    if not cwe:
        return {"status": "skip", "reason": "no CWE in path"}

    fn_name = _find_function_name(source, lang)
    total_lines = _count_lines(source)

    # Build in-memory DB
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)

    # Write fixture to temp dir
    with tempfile.TemporaryDirectory() as tmpdir:
        # Determine file path within "repo"
        if lang == "go":
            rel = f"pkg/{fixture_path.name}"
        elif lang == "java":
            rel = f"src/main/java/{fixture_path.name}"
        else:
            rel = fixture_path.name

        target = Path(tmpdir) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)

        # Insert synthetic signal
        con.execute("""
            INSERT INTO signals (scan_id, signal_type, cwe_id, file_path,
                containing_function, line_number, app_reachability, severity, is_final)
            VALUES (1, 'cwe', ?, ?, ?, 10, 'REACHABLE', 'HIGH', 0)
        """, (cwe, rel, fn_name))

        # Insert matching function
        con.execute("""
            INSERT INTO functions (scan_id, qname, short_name, file_path,
                language, line_number, end_line, is_reachable, is_entrypoint)
            VALUES (1, ?, ?, ?, ?, 1, ?, 1, 1)
        """, (f"pkg.{fn_name}", fn_name, rel, lang, total_lines))
        con.commit()

        # Run taint analysis
        try:
            result = run_taint_intra(con, 1, tmpdir, log_fn=lambda *a: None)
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "fixture": str(fixture_path.name),
                "expected": verdict,
            }

        # Check outcome: was the signal suppressed or exploitable?
        row = con.execute("""
            SELECT app_reachability, taint_phase, finalized_by, is_final
            FROM signals WHERE id = 1
        """).fetchone()

    was_suppressed = row["app_reachability"] == "NOT_REACHABLE"
    was_finalized = row["is_final"] == 1
    was_exploitable = was_finalized and not was_suppressed

    if verdict == "TRUE_NEGATIVE":
        # We expect the scanner to suppress (or at least not mark exploitable)
        passed = was_suppressed or not was_exploitable
    else:
        # TRUE_POSITIVE: signal should NOT be suppressed
        passed = not was_suppressed

    return {
        "status": "pass" if passed else "fail",
        "fixture": fixture_path.name,
        "expected": verdict,
        "actual_reachability": row["app_reachability"],
        "taint_phase": row["taint_phase"],
        "finalized_by": row["finalized_by"],
        "is_final": row["is_final"],
        "was_suppressed": was_suppressed,
        "was_exploitable": was_exploitable,
        "function": fn_name,
        "cwe": cwe,
        "language": lang,
    }


def main():
    parser = argparse.ArgumentParser(description="Run taint engine against v2 fixtures")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-o", "--output", type=str)
    parser.add_argument("--lang", type=str, help="Filter by language")
    parser.add_argument("--cwe", type=str, help="Filter by CWE dir (e.g. cwe78)")
    parser.add_argument("--fixture", type=str, help="Run single fixture by name")
    args = parser.parse_args()

    HERE = Path(__file__).resolve().parent
    fixtures_dir = HERE

    # Collect fixture files
    fixture_files = []
    for fpath in sorted(fixtures_dir.rglob("*")):
        if fpath.suffix not in LANG_MAP:
            continue
        if fpath.name in ("__init__.py", "validate_fixtures.py", "run_taint_engine.py"):
            continue
        if args.lang and args.lang not in str(fpath):
            continue
        if args.cwe and args.cwe not in str(fpath):
            continue
        if args.fixture and args.fixture not in fpath.name:
            continue
        fixture_files.append(fpath)

    print(f"Running taint engine against {len(fixture_files)} fixtures...")
    print(f"(reach-core: {REACH_CORE})")
    print()

    results = []
    by_status = defaultdict(int)
    by_cwe = defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0, "error": 0})
    by_lang = defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0, "error": 0})
    by_verdict = defaultdict(lambda: {"pass": 0, "fail": 0})
    failures = []

    for fpath in fixture_files:
        rel = fpath.relative_to(fixtures_dir)
        r = run_one_fixture(fpath, args.verbose)
        r["file"] = str(rel)
        results.append(r)

        status = r["status"]
        by_status[status] += 1

        cwe = r.get("cwe", "unknown")
        lang = r.get("language", "unknown")
        by_cwe[cwe][status] += 1
        by_lang[lang][status] += 1

        if status == "fail":
            by_verdict[r.get("expected", "?")]["fail"] += 1
            failures.append(r)
        elif status == "pass":
            by_verdict[r.get("expected", "?")]["pass"] += 1

        if args.verbose:
            icon = {"pass": "✓", "fail": "✗", "skip": "○", "error": "⚠"}[status]
            print(f"  {icon} {rel}  [{r.get('expected','?')}]", end="")
            if status == "fail":
                print(f"  (suppressed={r.get('was_suppressed')}, exploitable={r.get('was_exploitable')})", end="")
            elif status == "error":
                print(f"  ({r.get('error', '?')})", end="")
            print()

    # Print summary
    total = len(results)
    passed = by_status.get("pass", 0)
    failed = by_status.get("fail", 0)
    skipped = by_status.get("skip", 0)
    errors = by_status.get("error", 0)
    tested = passed + failed

    print()
    print("=" * 64)
    print(f"  TAINT ENGINE ACCURACY RESULTS")
    print("=" * 64)
    print(f"  Total fixtures:  {total}")
    print(f"  Tested:          {tested}  (skipped: {skipped}, errors: {errors})")
    print(f"  Passed:          {passed}")
    print(f"  Failed:          {failed}")
    if tested > 0:
        print(f"  Accuracy:        {passed/tested:.1%}")
    print()

    # Per-verdict
    for v in ("TRUE_POSITIVE", "TRUE_NEGATIVE"):
        vd = by_verdict.get(v, {"pass": 0, "fail": 0})
        t = vd["pass"] + vd["fail"]
        if t > 0:
            print(f"  {v}: {vd['pass']}/{t} correct ({vd['pass']/t:.0%})")

    # Per-CWE
    print()
    print(f"  {'CWE':<12} {'Pass':>6} {'Fail':>6} {'Skip':>6} {'Acc':>8}")
    print(f"  {'─'*12} {'─'*6} {'─'*6} {'─'*6} {'─'*8}")
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        t = c["pass"] + c["fail"]
        acc = f"{c['pass']/t:.0%}" if t > 0 else "n/a"
        print(f"  {cwe:<12} {c['pass']:>6} {c['fail']:>6} {c['skip']:>6} {acc:>8}")

    # Per-language
    print()
    print(f"  {'Language':<12} {'Pass':>6} {'Fail':>6} {'Skip':>6} {'Acc':>8}")
    print(f"  {'─'*12} {'─'*6} {'─'*6} {'─'*6} {'─'*8}")
    for lang in sorted(by_lang):
        l = by_lang[lang]
        t = l["pass"] + l["fail"]
        acc = f"{l['pass']/t:.0%}" if t > 0 else "n/a"
        print(f"  {lang:<12} {l['pass']:>6} {l['fail']:>6} {l['skip']:>6} {acc:>8}")

    # Failures detail
    if failures:
        print()
        print("  FAILURES:")
        for f in failures:
            print(f"    ✗ {f['file']}  expected={f['expected']}  "
                  f"suppressed={f.get('was_suppressed')}  "
                  f"exploitable={f.get('was_exploitable')}  "
                  f"fn={f.get('function')}")

    print("=" * 64)

    # JSON output
    if args.json:
        report = {
            "total": total, "tested": tested, "passed": passed,
            "failed": failed, "skipped": skipped, "errors": errors,
            "accuracy": round(passed / tested, 4) if tested > 0 else 0,
            "by_cwe": dict(by_cwe),
            "by_language": dict(by_lang),
            "failures": failures,
        }
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n  JSON report: {args.output}")
        else:
            print(json.dumps(report, indent=2, default=str))

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
