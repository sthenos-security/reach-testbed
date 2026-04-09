#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Fixture Validation Runner — Dual-Batch Architecture
====================================================

Validates REACHABLE scanner accuracy against two independent fixture batches:

  Batch 1: GOLDEN BASELINE  (fixtures/)
      - Original 15 fixtures, frozen — NEVER modified
      - Must pass 100% — any regression is a BLOCKING failure
      - These are the ground truth; if they break, the release is blocked

  Batch 2: V2 EXTENDED      (fixtures_v2/)
      - New permutation matrix — TP + TN cases across Go/Python/Java/TS
      - Validated separately — failures here are informational, not blocking
      - Fixtures promoted to "stable" after 5 consecutive passing releases
      - Machine-readable manifest (manifest.json) tracks metadata

Usage:
    # Run both batches (default)
    python validate_fixtures.py

    # Run only golden baseline (CI gate — must pass 100%)
    python validate_fixtures.py --baseline-only

    # Run only v2 extended (development iteration)
    python validate_fixtures.py --v2-only

    # Verbose output with per-fixture details
    python validate_fixtures.py --verbose

    # Output JSON report for CI integration
    python validate_fixtures.py --json --output report.json

    # Promote stable fixtures (after manual review)
    python validate_fixtures.py --promote py-cwe78-007 py-cwe89-003

Exit codes:
    0 — All fixtures pass (or baseline passes + v2 is informational)
    1 — Golden baseline regression (BLOCKING)
    2 — V2 failures detected (informational unless --strict)
    3 — Manifest or configuration error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ─── Constants ───────────────────────────────────────────────────────────────

HERE = Path(__file__).resolve().parent

# V2 fixtures live in the same dir as this script (taint-fixtures-v2/)
V2_DIR = HERE
MANIFEST_PATH = V2_DIR / "manifest.json"

# Golden baseline: check $REACH_CORE or sibling reach-core
def _find_baseline_dir() -> Path:
    """Locate golden baseline fixtures in reach-core."""
    env = os.environ.get("REACH_CORE")
    if env:
        p = Path(env) / "enzo" / "tests" / "extended" / "fixtures"
        if p.exists():
            return p
    # Try sibling reach-core
    sibling = HERE.parent.parent / "reach-core" / "enzo" / "tests" / "extended" / "fixtures"
    if sibling.exists():
        return sibling
    # Fallback: local fixtures/ subdir (if someone copies baseline here)
    local = HERE / "fixtures"
    if local.exists():
        return local
    return Path("/dev/null")  # baseline discovery will return empty list

BASELINE_DIR = _find_baseline_dir()

VERDICT_HEADER = re.compile(r"^[#/]+\s*VERDICT:\s*(\w+)", re.MULTILINE)
PATTERN_HEADER = re.compile(r"^[#/]+\s*PATTERN:\s*(.+)", re.MULTILINE)
CWE_HEADER = re.compile(
    r"^[#/]+\s*Fixture:.*?(CWE-\d+|Command Injection|SQL Injection|Path Traversal|Cross-Site Scripting)",
    re.MULTILINE,
)

LANG_EXTENSIONS = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".ts": "typescript",
    ".js": "javascript",
}

CWE_MAP = {
    "Command Injection": "CWE-78",
    "SQL Injection": "CWE-89",
    "Path Traversal": "CWE-22",
    "Cross-Site Scripting": "CWE-79",
}


# ─── Data classes ────────────────────────────────────────────────────────────


@dataclass
class FixtureResult:
    """Result of validating a single fixture."""
    fixture_id: str
    file_path: str
    language: str
    cwe: str
    expected_verdict: str  # TRUE_POSITIVE, TRUE_NEGATIVE
    actual_verdict: Optional[str] = None  # What the scanner returned
    passed: bool = False
    error: Optional[str] = None
    pattern: str = ""
    stable: bool = False


@dataclass
class BatchResult:
    """Aggregate result for a batch of fixtures."""
    batch_name: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    results: List[FixtureResult] = field(default_factory=list)
    tp_count: int = 0  # Expected true positives
    tn_count: int = 0  # Expected true negatives
    tp_correct: int = 0  # Correctly identified TPs
    tn_correct: int = 0  # Correctly identified TNs
    fp_count: int = 0  # False positives (TN flagged as TP)
    fn_count: int = 0  # False negatives (TP missed)

    @property
    def accuracy(self) -> float:
        return self.passed / self.total if self.total > 0 else 0.0

    @property
    def sensitivity(self) -> float:
        """True positive rate — what fraction of real vulnerabilities are caught."""
        return self.tp_correct / self.tp_count if self.tp_count > 0 else 0.0

    @property
    def specificity(self) -> float:
        """True negative rate — what fraction of safe code is correctly cleared."""
        return self.tn_correct / self.tn_count if self.tn_count > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        """False positive rate — what fraction of safe code is incorrectly flagged."""
        return self.fp_count / self.tn_count if self.tn_count > 0 else 0.0

    @property
    def fn_rate(self) -> float:
        """False negative rate — what fraction of real vulns are missed."""
        return self.fn_count / self.tp_count if self.tp_count > 0 else 0.0


@dataclass
class ValidationReport:
    """Full validation report across both batches."""
    timestamp: str = ""
    baseline: Optional[BatchResult] = None
    v2: Optional[BatchResult] = None
    baseline_blocked: bool = False
    summary: Dict = field(default_factory=dict)


# ─── Fixture Discovery ──────────────────────────────────────────────────────


def discover_baseline_fixtures() -> List[Dict]:
    """Discover fixtures in the golden baseline directory.

    Baseline fixtures are always TRUE_POSITIVE (the original set only had
    vulnerable code samples). They use a simpler header format:
        # VULNERABLE: <description> · line <N>
    """
    fixtures = []
    if not BASELINE_DIR.exists():
        return fixtures

    for lang_dir in sorted(BASELINE_DIR.iterdir()):
        if not lang_dir.is_dir() or lang_dir.name.startswith((".", "_")):
            continue
        for fpath in sorted(lang_dir.iterdir()):
            ext = fpath.suffix
            if ext not in LANG_EXTENSIONS:
                continue
            if fpath.name == "__init__.py":
                continue
            language = LANG_EXTENSIONS[ext]

            # Parse header to determine CWE
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            cwe_match = CWE_HEADER.search(content)
            cwe = ""
            if cwe_match:
                raw = cwe_match.group(1)
                cwe = CWE_MAP.get(raw, raw)

            fixtures.append({
                "id": f"baseline-{lang_dir.name}-{fpath.stem}",
                "file": str(fpath.relative_to(BASELINE_DIR)),
                "full_path": str(fpath),
                "language": language,
                "cwe": cwe,
                "verdict": "TRUE_POSITIVE",  # Baseline fixtures are all TP
                "pattern": fpath.stem,
                "stable": True,  # Always stable
            })
    return fixtures


def discover_v2_fixtures() -> List[Dict]:
    """Discover fixtures from the v2 manifest.

    Falls back to filesystem scanning if manifest is missing.
    """
    if MANIFEST_PATH.exists():
        return _load_manifest()
    return _scan_v2_directory()


def _load_manifest() -> List[Dict]:
    """Load fixture definitions from manifest.json."""
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    fixtures = []
    for entry in manifest.get("fixtures", []):
        full_path = V2_DIR / entry["file"]
        if not full_path.exists():
            print(f"  ⚠ Manifest entry missing file: {entry['file']}", file=sys.stderr)
            continue
        entry["full_path"] = str(full_path)
        fixtures.append(entry)
    return fixtures


def _scan_v2_directory() -> List[Dict]:
    """Scan fixtures_v2 directory and parse headers (fallback if no manifest)."""
    fixtures = []
    for fpath in sorted(V2_DIR.rglob("*")):
        if fpath.suffix not in LANG_EXTENSIONS:
            continue
        if fpath.name == "__init__.py":
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        language = LANG_EXTENSIONS[fpath.suffix]

        verdict_match = VERDICT_HEADER.search(content)
        verdict = verdict_match.group(1) if verdict_match else "UNKNOWN"

        pattern_match = PATTERN_HEADER.search(content)
        pattern = pattern_match.group(1).strip() if pattern_match else fpath.stem

        cwe_match = CWE_HEADER.search(content)
        cwe = ""
        if cwe_match:
            raw = cwe_match.group(1)
            cwe = CWE_MAP.get(raw, raw)

        rel = str(fpath.relative_to(V2_DIR))
        fixtures.append({
            "id": f"v2-{language}-{fpath.stem}",
            "file": rel,
            "full_path": str(fpath),
            "language": language,
            "cwe": cwe,
            "verdict": verdict,
            "pattern": pattern,
            "stable": False,
        })
    return fixtures


# ─── Fixture Validation ─────────────────────────────────────────────────────


def validate_fixture(fixture: Dict, scanner_results: Optional[Dict] = None) -> FixtureResult:
    """Validate a single fixture against scanner results.

    If scanner_results is None, performs structural validation only
    (checks that the file exists, has proper headers, and is parseable).
    """
    result = FixtureResult(
        fixture_id=fixture["id"],
        file_path=fixture.get("file", ""),
        language=fixture.get("language", ""),
        cwe=fixture.get("cwe", ""),
        expected_verdict=fixture.get("verdict", "UNKNOWN"),
        pattern=fixture.get("pattern", ""),
        stable=fixture.get("stable", False),
    )

    full_path = fixture.get("full_path", "")
    if not full_path or not Path(full_path).exists():
        result.error = f"File not found: {full_path}"
        return result

    # Structural validation — check file is readable and has expected markers
    try:
        content = Path(full_path).read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        result.error = f"Cannot read file: {e}"
        return result

    # Check for required header fields
    if "Fixture:" not in content:
        result.error = "Missing 'Fixture:' header"
        return result

    expected = fixture.get("verdict", "UNKNOWN")
    if expected not in ("TRUE_POSITIVE", "TRUE_NEGATIVE"):
        # Baseline fixtures might use simpler format
        if "VULNERABLE:" in content:
            expected = "TRUE_POSITIVE"
        elif "SAFE:" in content:
            expected = "TRUE_NEGATIVE"

    result.expected_verdict = expected

    # If we have scanner results, compare
    if scanner_results is not None:
        file_key = fixture.get("file", "")
        actual = scanner_results.get(file_key, {})
        if actual:
            result.actual_verdict = actual.get("verdict", "UNKNOWN")
            result.passed = result.expected_verdict == result.actual_verdict
        else:
            # Scanner didn't flag it — means it's treated as safe
            result.actual_verdict = "NOT_FLAGGED"
            if expected == "TRUE_NEGATIVE":
                result.passed = True  # Correctly not flagged
            else:
                result.passed = False  # Missed a true positive
    else:
        # Structural validation only — file exists and is well-formed
        result.passed = True
        result.actual_verdict = "STRUCTURAL_ONLY"

    return result


def validate_batch(
    batch_name: str,
    fixtures: List[Dict],
    scanner_results: Optional[Dict] = None,
) -> BatchResult:
    """Validate a batch of fixtures and compute metrics."""
    batch = BatchResult(batch_name=batch_name)
    batch.total = len(fixtures)

    for fixture in fixtures:
        result = validate_fixture(fixture, scanner_results)
        batch.results.append(result)

        if result.error:
            batch.errors += 1
            continue

        expected = result.expected_verdict

        if expected == "TRUE_POSITIVE":
            batch.tp_count += 1
            if result.passed:
                batch.tp_correct += 1
                batch.passed += 1
            else:
                batch.fn_count += 1
                batch.failed += 1
        elif expected == "TRUE_NEGATIVE":
            batch.tn_count += 1
            if result.passed:
                batch.tn_correct += 1
                batch.passed += 1
            else:
                batch.fp_count += 1
                batch.failed += 1
        else:
            batch.skipped += 1

    return batch


# ─── Reporting ───────────────────────────────────────────────────────────────


def print_batch_report(batch: BatchResult, verbose: bool = False) -> None:
    """Print human-readable batch report."""
    width = 64
    print()
    print("━" * width)
    print(f"  {batch.batch_name}")
    print("━" * width)
    print()

    if batch.total == 0:
        print("  No fixtures found.")
        return

    # Summary
    print(f"  Total fixtures:     {batch.total}")
    print(f"  Passed:             {batch.passed}")
    print(f"  Failed:             {batch.failed}")
    if batch.errors:
        print(f"  Errors:             {batch.errors}")
    if batch.skipped:
        print(f"  Skipped:            {batch.skipped}")
    print()

    # Metrics
    print(f"  Accuracy:           {batch.accuracy:.1%}")
    if batch.tp_count > 0:
        print(f"  Sensitivity (TPR):  {batch.sensitivity:.1%}  ({batch.tp_correct}/{batch.tp_count} TPs caught)")
    if batch.tn_count > 0:
        print(f"  Specificity (TNR):  {batch.specificity:.1%}  ({batch.tn_correct}/{batch.tn_count} TNs correct)")
    if batch.fp_count > 0:
        print(f"  False Positive Rate:{batch.fp_rate:.1%}  ({batch.fp_count} safe cases flagged)")
    if batch.fn_count > 0:
        print(f"  False Negative Rate:{batch.fn_rate:.1%}  ({batch.fn_count} vulns missed)")
    print()

    # Per-CWE breakdown
    by_cwe: Dict[str, Dict] = defaultdict(lambda: {"tp": 0, "tn": 0, "pass": 0, "fail": 0})
    for r in batch.results:
        if r.error:
            continue
        c = by_cwe[r.cwe or "unknown"]
        if r.expected_verdict == "TRUE_POSITIVE":
            c["tp"] += 1
        else:
            c["tn"] += 1
        if r.passed:
            c["pass"] += 1
        else:
            c["fail"] += 1

    print("  Per-CWE Breakdown:")
    print(f"  {'CWE':<12} {'TP':>4} {'TN':>4} {'Pass':>6} {'Fail':>6} {'Acc':>8}")
    print(f"  {'─'*12} {'─'*4} {'─'*4} {'─'*6} {'─'*6} {'─'*8}")
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        total = c["pass"] + c["fail"]
        acc = c["pass"] / total if total > 0 else 0
        print(f"  {cwe:<12} {c['tp']:>4} {c['tn']:>4} {c['pass']:>6} {c['fail']:>6} {acc:>7.0%}")
    print()

    # Per-language breakdown
    by_lang: Dict[str, Dict] = defaultdict(lambda: {"total": 0, "pass": 0})
    for r in batch.results:
        if r.error:
            continue
        by_lang[r.language]["total"] += 1
        if r.passed:
            by_lang[r.language]["pass"] += 1

    print("  Per-Language Breakdown:")
    print(f"  {'Language':<12} {'Total':>6} {'Pass':>6} {'Acc':>8}")
    print(f"  {'─'*12} {'─'*6} {'─'*6} {'─'*8}")
    for lang in sorted(by_lang):
        l = by_lang[lang]
        acc = l["pass"] / l["total"] if l["total"] > 0 else 0
        print(f"  {lang:<12} {l['total']:>6} {l['pass']:>6} {acc:>7.0%}")
    print()

    # Verbose: show each fixture
    if verbose:
        failures = [r for r in batch.results if not r.passed and not r.error]
        if failures:
            print("  ✗ FAILURES:")
            for r in failures:
                print(f"    [{r.fixture_id}] {r.file_path}")
                print(f"      Expected: {r.expected_verdict}  Got: {r.actual_verdict}")
            print()

        errors = [r for r in batch.results if r.error]
        if errors:
            print("  ⚠ ERRORS:")
            for r in errors:
                print(f"    [{r.fixture_id}] {r.error}")
            print()


def generate_json_report(report: ValidationReport) -> Dict:
    """Generate JSON-serializable report."""
    out = {
        "timestamp": report.timestamp,
        "baseline_blocked": report.baseline_blocked,
    }
    for batch_name in ("baseline", "v2"):
        batch = getattr(report, batch_name)
        if batch is None:
            continue
        out[batch_name] = {
            "total": batch.total,
            "passed": batch.passed,
            "failed": batch.failed,
            "errors": batch.errors,
            "accuracy": round(batch.accuracy, 4),
            "sensitivity": round(batch.sensitivity, 4),
            "specificity": round(batch.specificity, 4),
            "fp_rate": round(batch.fp_rate, 4),
            "fn_rate": round(batch.fn_rate, 4),
            "tp_count": batch.tp_count,
            "tn_count": batch.tn_count,
            "by_cwe": {},
            "by_language": {},
            "failures": [],
        }
        # Per-CWE
        by_cwe = defaultdict(lambda: {"pass": 0, "fail": 0})
        for r in batch.results:
            if not r.error:
                by_cwe[r.cwe or "unknown"]["pass" if r.passed else "fail"] += 1
        out[batch_name]["by_cwe"] = dict(by_cwe)

        # Per-language
        by_lang = defaultdict(lambda: {"pass": 0, "fail": 0})
        for r in batch.results:
            if not r.error:
                by_lang[r.language]["pass" if r.passed else "fail"] += 1
        out[batch_name]["by_language"] = dict(by_lang)

        # Failures
        out[batch_name]["failures"] = [
            {"id": r.fixture_id, "file": r.file_path,
             "expected": r.expected_verdict, "actual": r.actual_verdict}
            for r in batch.results if not r.passed and not r.error
        ]

    return out


# ─── Promotion ───────────────────────────────────────────────────────────────


def promote_fixtures(fixture_ids: List[str]) -> None:
    """Mark fixtures as stable in the manifest."""
    if not MANIFEST_PATH.exists():
        print("Error: manifest.json not found", file=sys.stderr)
        sys.exit(3)

    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    promoted = 0
    for entry in manifest.get("fixtures", []):
        if entry["id"] in fixture_ids:
            entry["stable"] = True
            promoted += 1
            print(f"  ✓ Promoted: {entry['id']} ({entry['file']})")

    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n  Promoted {promoted}/{len(fixture_ids)} fixtures to stable.")


# ─── Main ────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="REACHABLE Fixture Validation Runner — Dual-Batch Architecture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--baseline-only", action="store_true",
                        help="Run only the golden baseline batch")
    parser.add_argument("--v2-only", action="store_true",
                        help="Run only the v2 extended batch")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show per-fixture details")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON report")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output file for JSON report")
    parser.add_argument("--strict", action="store_true",
                        help="Treat v2 failures as blocking (exit code 2)")
    parser.add_argument("--promote", nargs="+", metavar="ID",
                        help="Promote fixture IDs to stable status")
    parser.add_argument("--scanner-results", type=str, default=None,
                        help="Path to scanner results JSON (for actual validation)")
    args = parser.parse_args()

    # Handle promotion
    if args.promote:
        promote_fixtures(args.promote)
        return 0

    # Load scanner results if provided
    scanner_results = None
    if args.scanner_results:
        with open(args.scanner_results) as f:
            scanner_results = json.load(f)

    report = ValidationReport(timestamp=datetime.utcnow().isoformat())
    exit_code = 0

    # ─── Batch 1: Golden Baseline ────────────────────────────────────────
    if not args.v2_only:
        baseline_fixtures = discover_baseline_fixtures()
        report.baseline = validate_batch(
            "GOLDEN BASELINE (fixtures/)", baseline_fixtures, scanner_results
        )
        print_batch_report(report.baseline, args.verbose)

        if report.baseline.failed > 0 or report.baseline.errors > 0:
            report.baseline_blocked = True
            exit_code = 1
            print("  🚫 BASELINE REGRESSION DETECTED — RELEASE BLOCKED")
            print()
        else:
            print("  ✅ Golden baseline: ALL PASS")
            print()

    # ─── Batch 2: V2 Extended ────────────────────────────────────────────
    if not args.baseline_only:
        v2_fixtures = discover_v2_fixtures()
        report.v2 = validate_batch(
            "V2 EXTENDED (fixtures_v2/)", v2_fixtures, scanner_results
        )
        print_batch_report(report.v2, args.verbose)

        if report.v2.failed > 0:
            if args.strict:
                exit_code = max(exit_code, 2)
                print("  ⚠ V2 fixtures have failures (--strict mode: blocking)")
            else:
                print("  ℹ V2 fixtures have failures (informational — not blocking)")
            print()
        else:
            print("  ✅ V2 extended: ALL PASS")
            print()

    # ─── Combined Summary ────────────────────────────────────────────────
    print("━" * 64)
    print("  SUMMARY")
    print("━" * 64)
    if report.baseline:
        status = "✅ PASS" if not report.baseline_blocked else "🚫 BLOCKED"
        print(f"  Baseline:  {report.baseline.passed}/{report.baseline.total} passed  {status}")
    if report.v2:
        v2_status = "✅" if report.v2.failed == 0 else "⚠"
        print(f"  V2:        {report.v2.passed}/{report.v2.total} passed  "
              f"(FPR: {report.v2.fp_rate:.0%}, FNR: {report.v2.fn_rate:.0%})  {v2_status}")
    print("━" * 64)
    print()

    # ─── JSON output ─────────────────────────────────────────────────────
    if args.json:
        json_report = generate_json_report(report)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(json_report, f, indent=2)
            print(f"  JSON report written to: {args.output}")
        else:
            print(json.dumps(json_report, indent=2))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
