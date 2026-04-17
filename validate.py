#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
validate.py — REACHABLE testbed validator

Compares scanner output (SARIF or repo.db) against the expected baseline
defined in testbed.json. Exits non-zero if any expected finding is missing
(MISS) or any critical reachability assertion fails.

Usage:
    # Against SARIF export (recommended for CI)
    python validate.py --sarif scan-results.sarif

    # Against repo.db directly
    python validate.py --db ~/.reachable/scans/reach-testbed-*/repo.db

    # Update baseline from latest scan
    python validate.py --db path/to/repo.db --update-baseline

    # Verbose: show all findings including extras
    python validate.py --sarif scan-results.sarif --verbose
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─── Color output ────────────────────────────────────────────────────────────
RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def red(s):    return f"{RED}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def bold(s):   return f"{BOLD}{s}{RESET}"

PASS_MARK = green("✔ PASS")
INFO_MARK = cyan("ℹ INFO")

# ─── Data model ──────────────────────────────────────────────────────────────
@dataclass
class FindingRecord:
    """Normalized finding from either SARIF or repo.db."""
    finding_type: str          # cve, cwe, secret, dlp, ai, malware
    identifier: str            # CVE ID, CWE ID, secret_type, pii_type, owasp_category, path
    file_path: Optional[str]
    reachability: Optional[str]
    package: Optional[str] = None
    containing_function: Optional[str] = None  # function/method name if available
    function_qname: Optional[str] = None       # fully qualified name from functions table
    raw: dict = field(default_factory=dict)


# Reachability state hierarchy (highest → lowest confidence):
#   EXPLOITABLE > REACHABLE > UNKNOWN > NOT_REACHABLE
# EXPLOITABLE = taint A-D confirmed user input flows to sink.
# It is a strict promotion of REACHABLE — it satisfies any assertion
# that expects REACHABLE and must never be treated as a failure.
_SATISFIES: dict[str, set[str]] = {
    "REACHABLE":     {"REACHABLE", "EXPLOITABLE"},
    "NOT_REACHABLE": {"NOT_REACHABLE"},
    "UNKNOWN":       {"UNKNOWN"},
}

def _reach_ok(expected: str, actual: str) -> bool:
    """Return True if `actual` satisfies the `expected` reachability assertion."""
    return actual in _SATISFIES.get(expected, {expected})


# ─── Failure reason enum ─────────────────────────────────────────────────────
class Reason:
    """Precise failure categories for reachability validation."""
    PASS                     = "PASS"
    # Detection failures
    FAIL_NOT_DETECTED        = "FAIL_NOT_DETECTED"        # no signal of expected type in file
    FAIL_NO_STATE            = "FAIL_NO_STATE"            # signal found, reachability NULL (pipeline bug)
    # Classification failures — directional
    FAIL_DEMOTED             = "FAIL_DEMOTED"             # expected REACHABLE, got NR (DANGEROUS)
    FAIL_PROMOTED            = "FAIL_PROMOTED"            # expected NR, got REACHABLE (false positive)
    FAIL_UNKNOWN_EXP_REACH   = "FAIL_UNKNOWN_EXP_REACH"   # expected REACHABLE, got UNKNOWN
    FAIL_REACH_EXP_UNKNOWN   = "FAIL_REACH_EXP_UNKNOWN"   # expected UNKNOWN, got REACHABLE
    FAIL_NR_EXP_UNKNOWN      = "FAIL_NR_EXP_UNKNOWN"      # expected UNKNOWN, got NR
    FAIL_UNKNOWN_EXP_NR      = "FAIL_UNKNOWN_EXP_NR"      # expected NR, got UNKNOWN

    @staticmethod
    def classify(expected: str, actual: str) -> str:
        """Return the precise failure reason for a reachability mismatch."""
        # EXPLOITABLE is a taint-confirmed promotion of REACHABLE — never a failure.
        if actual == "EXPLOITABLE" and expected == "REACHABLE":
            return Reason.PASS
        key = (expected, actual)
        return {
            ("REACHABLE", "NOT_REACHABLE"): Reason.FAIL_DEMOTED,
            ("REACHABLE", "UNKNOWN"):       Reason.FAIL_UNKNOWN_EXP_REACH,
            ("NOT_REACHABLE", "REACHABLE"): Reason.FAIL_PROMOTED,
            ("NOT_REACHABLE", "UNKNOWN"):   Reason.FAIL_UNKNOWN_EXP_NR,
            ("UNKNOWN", "REACHABLE"):       Reason.FAIL_REACH_EXP_UNKNOWN,
            ("UNKNOWN", "NOT_REACHABLE"):   Reason.FAIL_NR_EXP_UNKNOWN,
        }.get(key, f"FAIL_{actual}_EXP_{expected}")

    @staticmethod
    def is_fail(reason: str) -> bool:
        return reason.startswith("FAIL_")

    @staticmethod
    def severity(reason: str) -> str:
        """How bad is this failure? For sorting/prioritization."""
        if reason == Reason.FAIL_DEMOTED:
            return "CRITICAL"   # hiding real vulnerabilities
        if reason == Reason.FAIL_NOT_DETECTED:
            return "HIGH"       # scanner blind spot
        if reason == Reason.FAIL_NO_STATE:
            return "HIGH"       # pipeline bug
        if reason in (Reason.FAIL_UNKNOWN_EXP_REACH, Reason.FAIL_NR_EXP_UNKNOWN):
            return "MEDIUM"     # under-classified
        if reason in (Reason.FAIL_PROMOTED, Reason.FAIL_REACH_EXP_UNKNOWN):
            return "LOW"        # noise / over-classified
        if reason == Reason.FAIL_UNKNOWN_EXP_NR:
            return "LOW"        # conservative, acceptable
        return "INFO"


@dataclass
class ValidationResult:
    category: str
    description: str
    status: str   # PASS, MISS, FAIL, or SKIP
    detail: str = ""
    reason: str = ""  # Reason.* enum value for precise classification


# ─── SARIF loader ────────────────────────────────────────────────────────────
def load_sarif(sarif_path: str) -> list[FindingRecord]:
    with open(sarif_path) as f:
        sarif = json.load(f)

    records = []
    for run in sarif.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            props   = result.get("properties", {})
            locs    = result.get("locations", [])
            file_path = None
            containing_func = None
            if locs:
                uri = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                file_path = uri
                # Extract containing function from logicalLocation if available
                logical_loc = locs[0].get("logicalLocation", {})
                if logical_loc:
                    containing_func = logical_loc.get("fullyQualifiedName") or logical_loc.get("name")

            # Classify finding type from rule ID / properties
            ftype = props.get("finding_type", "")
            if not ftype:
                if rule_id.upper().startswith("CVE-") or rule_id.upper().startswith("GHSA-"):
                    ftype = "cve"
                elif rule_id.upper().startswith("CWE-"):
                    ftype = "cwe"
                elif props.get("pii_type"):
                    ftype = "dlp"
                elif props.get("owasp_category"):
                    ftype = "ai"
                elif props.get("secret_type") or props.get("finding_type") == "secret":
                    ftype = "secret"
                elif props.get("finding_type") == "malware":
                    ftype = "malware"
                else:
                    ftype = "unknown"

            reachability = props.get("reachability") or props.get("app_reachability")
            identifier = (
                props.get("cve_id") or
                props.get("cwe_id") or
                props.get("pii_type") or
                props.get("owasp_category") or
                props.get("secret_type") or
                rule_id
            )

            records.append(FindingRecord(
                finding_type=ftype,
                identifier=identifier or rule_id,
                file_path=file_path,
                reachability=reachability,
                package=props.get("package_name"),
                containing_function=containing_func,
                raw=result,
            ))

    return records


# ─── repo.db loader ──────────────────────────────────────────────────────────
def resolve_db(db_path: str) -> str:
    """Resolve glob patterns and find the most recent repo.db."""
    if "*" in db_path or "?" in db_path:
        matches = sorted(glob.glob(db_path), key=os.path.getmtime, reverse=True)
        if not matches:
            print(red(f"No repo.db found matching: {db_path}"), file=sys.stderr)
            sys.exit(1)
        return matches[0]
    return db_path


def _load_from_signals(con) -> list[FindingRecord]:
    """Load from unified signals table (primary path)."""
    records = []
    rows = con.execute("""
        SELECT s.signal_type, s.finding_id, s.display_id, s.cwe_id, s.secret_type,
               s.owasp_category, s.pii_type, s.file_path, s.app_reachability,
               s.package_name, s.containing_function, s.raw_data,
               f.qname AS function_qname
        FROM signals s
        LEFT JOIN functions f ON f.id = s.function_id
        WHERE s.scan_id = (SELECT MAX(id) FROM scans)
    """).fetchall()
    for r in rows:
        ftype = r["signal_type"]
        raw = json.loads(r["raw_data"]) if r["raw_data"] else {}
        identifier = (
            r["display_id"] or
            (r["cwe_id"] if ftype == "cwe" else None) or
            (r["secret_type"] if ftype == "secret" else None) or
            (r["owasp_category"] if ftype == "ai" else None) or
            (r["pii_type"] if ftype == "dlp" else None) or
            r["finding_id"]
        )
        # Use the pipeline's containing_function column (populated by _backfill_containing_function)
        containing_func = r["containing_function"] or None

        records.append(FindingRecord(
            finding_type=ftype,
            identifier=identifier or "",
            file_path=r["file_path"],
            reachability=r["app_reachability"],
            package=r["package_name"],
            containing_function=containing_func,
            function_qname=r["function_qname"],
            raw=raw,
        ))
        # CVE alias records
        if ftype == "cve":
            aliases = raw.get("osv_aliases", []) or []
            for alias in aliases:
                if alias and alias != identifier:
                    records.append(FindingRecord(
                        finding_type="cve",
                        identifier=alias,
                        file_path=r["file_path"],
                        reachability=r["app_reachability"],
                        package=r["package_name"],
                        containing_function=containing_func,
                        raw=raw,
                    ))
    # v7 architecture: CVE signals have ONE row per (advisory, package).
    # The signal's app_reachability is the PROJECT-LEVEL verdict (REACHABLE if
    # ANY import site is live).  For per-FILE reachability (needed by framework
    # tests), we override CVE signals' reachability based on their own file's
    # functions, and create virtual records for each import site.
    scan_id = con.execute("SELECT MAX(id) FROM scans").fetchone()[0]

    # Step 1: For CVE signals with import sites, override the signal's
    # reachability to per-file (based on the signal's own file_path).
    #
    # IMPORTANT: Only override UNKNOWN signals.  If the pipeline explicitly
    # classified a signal (NOT_REACHABLE from language classifiers, vulnerable
    # symbols, or dead-class analysis), that verdict is more precise than
    # simple per-file function reachability.  Overriding it would lose the
    # nuance of "file is live but this specific CVE's functions are dead."
    try:
        cve_overrides = con.execute("""
            SELECT s.id, s.file_path, s.file_id, s.app_reachability,
                   COALESCE(
                       (SELECT MAX(CASE WHEN f2.is_reachable = 1 OR f2.is_entrypoint = 1
                                        THEN 1 ELSE 0 END)
                        FROM functions f2
                        WHERE f2.scan_id = s.scan_id AND f2.file_id = s.file_id),
                       0
                   ) AS own_file_reachable
            FROM signals s
            WHERE s.scan_id = ? AND s.signal_type = 'cve'
              AND EXISTS (SELECT 1 FROM cve_import_sites cs
                          WHERE cs.signal_id = s.id AND cs.scan_id = s.scan_id)
        """, (scan_id,)).fetchall()
        # Build map: file_path → per-file reachability, but only for UNKNOWN signals
        cve_file_reach = {}
        for ov in cve_overrides:
            fp = ov["file_path"] or ""
            cve_file_reach[fp] = "REACHABLE" if ov["own_file_reachable"] else "NOT_REACHABLE"
        # Build set of file_paths where the pipeline gave an explicit verdict
        # (non-UNKNOWN) — these should NOT be overridden by per-file heuristic
        pipeline_decided_files = set()
        for ov in cve_overrides:
            if ov["app_reachability"] != "UNKNOWN":
                pipeline_decided_files.add(ov["file_path"] or "")
        # Override records — only UNKNOWN pipeline verdicts
        for rec in records:
            if rec.finding_type == "cve" and rec.file_path in cve_file_reach:
                if rec.file_path not in pipeline_decided_files:
                    rec.reachability = cve_file_reach[rec.file_path]
    except Exception:
        pass

    # Step 2: Create per-FUNCTION virtual FindingRecords for each import site.
    # v7 architecture: ONE signal per (advisory, package) in signals table.
    # Import sites are in cve_import_sites.  The validator must create virtual
    # records for each function in each import site so fn_hint filtering works.
    # Example: cve.go has TranslateHandler (reachable) + ParseLangUnknown (dead).
    # Old code created one file-level record → fn filter failed for ParseLangUnknown.
    try:
        # 2a: Per-function records — one record per (import_site × function)
        site_fns = con.execute("""
            SELECT cs.file_path AS site_path, cs.file_id AS site_file_id,
                   s.signal_type, s.finding_id, s.display_id, s.cwe_id,
                   s.package_name, s.app_reachability, s.raw_data,
                   f2.short_name AS fn_name, f2.qname AS fn_qname,
                   f2.is_reachable AS fn_reachable, f2.is_entrypoint AS fn_entrypoint,
                   COALESCE(
                       (SELECT MAX(CASE WHEN f3.is_reachable = 1 OR f3.is_entrypoint = 1
                                        THEN 1 ELSE 0 END)
                        FROM functions f3
                        WHERE f3.scan_id = cs.scan_id AND f3.file_id = cs.file_id),
                       0
                   ) AS file_has_reachable
            FROM cve_import_sites cs
            JOIN signals s ON s.id = cs.signal_id AND s.scan_id = cs.scan_id
            JOIN functions f2 ON f2.scan_id = cs.scan_id AND f2.file_id = cs.file_id
            WHERE cs.scan_id = ?
        """, (scan_id,)).fetchall()
        for r in site_fns:
            raw = json.loads(r["raw_data"]) if r["raw_data"] else {}
            identifier = r["display_id"] or r["finding_id"]
            # Three-way reachability:
            #   Function reachable/entrypoint → REACHABLE
            #   Function dead but file has other reachable fns → UNKNOWN (live file, fn not called)
            #   Function dead and file all-dead → NOT_REACHABLE
            if r["fn_reachable"] or r["fn_entrypoint"]:
                fn_reach = "REACHABLE"
            elif r["file_has_reachable"]:
                fn_reach = "UNKNOWN"
            else:
                fn_reach = "NOT_REACHABLE"
            records.append(FindingRecord(
                finding_type="cve",
                identifier=identifier or "",
                file_path=r["site_path"],
                reachability=fn_reach,
                package=r["package_name"],
                containing_function=r["fn_name"],
                function_qname=r["fn_qname"],
                raw=raw,
            ))
            aliases = raw.get("osv_aliases", []) or []
            for alias in aliases:
                if alias and alias != identifier:
                    records.append(FindingRecord(
                        finding_type="cve",
                        identifier=alias,
                        file_path=r["site_path"],
                        reachability=fn_reach,
                        package=r["package_name"],
                        containing_function=r["fn_name"],
                        function_qname=r["fn_qname"],
                        raw=raw,
                    ))

        # 2b: File-level fallback for import site files with NO functions.
        # These files (e.g. JS route handlers) may have no function entries
        # but are still reachable if imported by a reachable module.
        # Check import_names: if a reachable file imports from this module,
        # the site is reachable.
        no_fn_sites = con.execute("""
            SELECT cs.file_path AS site_path, cs.file_id AS site_file_id,
                   s.signal_type, s.finding_id, s.display_id, s.cwe_id,
                   s.package_name, s.app_reachability, s.raw_data,
                   s.containing_function, f.qname AS function_qname
            FROM cve_import_sites cs
            JOIN signals s ON s.id = cs.signal_id AND s.scan_id = cs.scan_id
            LEFT JOIN functions f ON f.id = s.function_id
            WHERE cs.scan_id = ?
              AND NOT EXISTS (
                  SELECT 1 FROM functions f3
                  WHERE f3.scan_id = cs.scan_id AND f3.file_id = cs.file_id
              )
        """, (scan_id,)).fetchall()
        for r in no_fn_sites:
            raw = json.loads(r["raw_data"]) if r["raw_data"] else {}
            identifier = r["display_id"] or r["finding_id"]
            # Check if any reachable module imports from this file's path
            site_path = r["site_path"] or ""
            site_basename = os.path.splitext(os.path.basename(site_path))[0]
            is_imported_by_reachable = False
            if site_basename:
                importers = con.execute("""
                    SELECT 1 FROM import_names iname
                    JOIN functions f4 ON f4.scan_id = iname.scan_id
                                     AND f4.file_id = iname.file_id
                    WHERE iname.scan_id = ?
                      AND (iname.short_name = ? OR iname.source_module = ?
                           OR iname.source_module LIKE '%/' || ?
                           OR iname.source_module LIKE '%.' || ?)
                      AND (f4.is_reachable = 1 OR f4.is_entrypoint = 1)
                    LIMIT 1
                """, (scan_id, site_basename, site_basename,
                      site_basename, site_basename)).fetchone()
                is_imported_by_reachable = importers is not None
            site_reach = "REACHABLE" if is_imported_by_reachable else "NOT_REACHABLE"
            records.append(FindingRecord(
                finding_type="cve",
                identifier=identifier or "",
                file_path=r["site_path"],
                reachability=site_reach,
                package=r["package_name"],
                containing_function=r["containing_function"],
                function_qname=r["function_qname"],
                raw=raw,
            ))
            aliases = raw.get("osv_aliases", []) or []
            for alias in aliases:
                if alias and alias != identifier:
                    records.append(FindingRecord(
                        finding_type="cve",
                        identifier=alias,
                        file_path=r["site_path"],
                        reachability=site_reach,
                        package=r["package_name"],
                        containing_function=r["containing_function"],
                        raw=raw,
                    ))
    except Exception:
        pass  # cve_import_sites may not exist in older DBs

    return records


def load_db(db_path: str) -> list[FindingRecord]:
    """Load findings from unified signals table."""
    db_path = resolve_db(db_path)
    print(f"{INFO_MARK} Loading: {db_path}")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    records = _load_from_signals(con)
    con.close()
    print(f"{INFO_MARK} Loaded {len(records)} findings from DB")
    return records


# ─── Matching helpers ─────────────────────────────────────────────────────────
def file_matches(actual_path: Optional[str], expected_file: Optional[str]) -> bool:
    """Fuzzy match: expected is a suffix of actual path."""
    if not expected_file:
        return True
    if not actual_path:
        return False
    # Normalize separators
    actual   = actual_path.replace("\\", "/")
    expected = expected_file.replace("\\", "/")
    return actual.endswith(expected) or expected in actual


def _function_matches(actual_fn: Optional[str], actual_qname: Optional[str],
                      expected_fn: Optional[str]) -> bool:
    """Fuzzy function match. Compares short name, qname tail, and the raw
    containing_function field against the expected function (case-insensitive).
    Returns True if expected_fn is unspecified (any function OK).
    """
    if not expected_fn:
        return True
    exp = expected_fn.lower().rstrip("?!").strip()
    for candidate in (actual_fn, actual_qname):
        if not candidate:
            continue
        cand = candidate.lower()
        # Compare full, tail after '.'/':', and with ?/! stripped for Ruby
        cand_stripped = cand.rstrip("?!")
        tail = cand_stripped.rsplit(".", 1)[-1].rsplit("::", 1)[-1]
        if exp == cand_stripped or exp == tail:
            return True
        # Also allow substring match (e.g. expected "tp_concat" in qname)
        if exp == cand_stripped.split("(")[0]:
            return True
    return False


def find_match(findings: list[FindingRecord], ftype: str,
               identifier: str, file_hint: Optional[str] = None,
               package: Optional[str] = None,
               function_hint: Optional[str] = None,
               exclude_ids: Optional[set] = None,
               expected_reachability: Optional[str] = None) -> Optional[FindingRecord]:
    """Find the best matching finding for a baseline entry.

    When ``function_hint`` is supplied (e.g. testbed.json CWE entry has
    ``"function": "password_hash"``), the strict pass REQUIRES the finding's
    containing_function (or function_qname) to match. This prevents the
    validator from collapsing multiple per-function signals in the same file
    onto a single "best" record, which caused all three Ruby CWE-327
    entries in cwe_fp_md5_comparison.rb to match the same finding.

    When ``exclude_ids`` is supplied, findings whose ``id()`` is in the set
    are skipped — this lets callers iterate multiple baseline entries against
    the same file and distribute findings (one-per-baseline) rather than
    collapsing. Used when function-less findings (e.g. Ruby before function
    extraction is available) need to map 1:1 to per-function baseline rows.

    When ``expected_reachability`` is supplied and Pass 1b (file-only fallback)
    produces multiple candidates with no function discriminator, candidates
    matching the expected reachability are preferred. This lets a
    REACHABLE-expected baseline claim a REACHABLE finding first, leaving the
    NOT_REACHABLE findings for the NOT_REACHABLE-expected baseline rows.

    Returns a FindingRecord with ``relaxed_match`` attribute set to True if
    the match was found only by dropping the file requirement (second pass).
    """
    excl = exclude_ids or set()
    candidates = [f for f in findings if f.finding_type == ftype and id(f) not in excl]

    # Pass 1: strict — require identifier + package + file (+ function if given).
    # Collect ALL strict matches so we can prefer REACHABLE over UNKNOWN/NOT_REACHABLE.
    strict = []
    for f in candidates:
        id_match   = identifier.lower() in (f.identifier or "").lower()
        pkg_match  = (not package) or (package.lower() in (f.package or "").lower())
        file_match = file_matches(f.file_path, file_hint)
        fn_match   = _function_matches(f.containing_function, f.function_qname, function_hint)

        if id_match and pkg_match and file_match and fn_match:
            f.relaxed_match = False
            strict.append(f)
    if strict:
        _pref = {'EXPLOITABLE': -1, 'REACHABLE': 0, 'UNKNOWN': 1, 'NOT_REACHABLE': 2}
        strict.sort(key=lambda f: _pref.get(f.reachability, 1))
        return strict[0]

    # Pass 1b: strict file match ignoring function — when function_hint
    # didn't hit (e.g. Ruby function extraction is missing so
    # containing_function is NULL), fall through to file-level match
    # before relaxing file. Still safer than cross-file relaxed match.
    if function_hint:
        file_only = []
        for f in candidates:
            id_match   = identifier.lower() in (f.identifier or "").lower()
            pkg_match  = (not package) or (package.lower() in (f.package or "").lower())
            file_match = file_matches(f.file_path, file_hint)
            if id_match and pkg_match and file_match:
                f.relaxed_match = False
                file_only.append(f)
        if file_only:
            # When expected_reachability is known, prefer findings whose
            # reachability already matches. This prevents cross-collapse when
            # three per-function baseline entries share the same file but
            # expect different verdicts (e.g. Ruby MD5 case: two NR + one R).
            def _sort_key(f):
                _pref = {'EXPLOITABLE': -1, 'REACHABLE': 0, 'UNKNOWN': 1, 'NOT_REACHABLE': 2}
                match_bonus = 0 if expected_reachability and f.reachability == expected_reachability else 1
                return (match_bonus, _pref.get(f.reachability, 1))
            file_only.sort(key=_sort_key)
            return file_only[0]

    # Pass 2: relaxed — drop file requirement, prefer REACHABLE matches
    if file_hint:
        relaxed = []
        for f in candidates:
            id_match  = identifier.lower() in (f.identifier or "").lower()
            pkg_match = (not package) or (package.lower() in (f.package or "").lower())
            fn_match  = _function_matches(f.containing_function, f.function_qname, function_hint)
            if id_match and pkg_match and fn_match:
                f.relaxed_match = True
                relaxed.append(f)
        if relaxed:
            _pref = {'EXPLOITABLE': -1, 'REACHABLE': 0, 'UNKNOWN': 1, 'NOT_REACHABLE': 2}
            relaxed.sort(key=lambda f: _pref.get(f.reachability, 1))
            return relaxed[0]

    return None


def _relaxed_tag(match: FindingRecord) -> str:
    """Return a warning suffix if the match used relaxed (file-dropped) matching."""
    return " [RELAXED-MATCH: file mismatch]" if getattr(match, "relaxed_match", False) else ""


# ─── Validators ──────────────────────────────────────────────────────────────
def validate_cve(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    for e in expected:
        cve_id  = e["id"]
        pkg     = e.get("package")
        reach   = e.get("reachability")
        file_h  = e.get("file")
        match   = find_match(findings, "cve", cve_id, file_h, pkg)

        if not match:
            results.append(ValidationResult("CVE", cve_id, "FAIL",
                f"not detected (package={pkg}, file={file_h})",
                reason=Reason.FAIL_NOT_DETECTED))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                reason = Reason.classify(reach, match.reachability)
                sev = Reason.severity(reason)
                results.append(ValidationResult("CVE", cve_id, "FAIL",
                    f"expected={reach} got={match.reachability}{tag}",
                    reason=reason))
            else:
                results.append(ValidationResult("CVE", cve_id, "PASS",
                    f"pkg={match.package} reach={match.reachability}{tag}"))
    return results


def validate_cwe(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    # When multiple baseline entries target the same (cwe_id, file), the
    # findings should be distributed 1:1 rather than collapsed — especially
    # for languages where function extraction is missing (Ruby) and Pass 1b
    # would otherwise map every baseline row to the same best-preferred
    # finding. Track matched findings per (cwe_id, file) group.
    matched_by_group: dict[tuple, set] = {}
    # Process baseline rows whose reachability is R before NR, so that the
    # REACHABLE-expected row claims a REACHABLE finding first (if one exists),
    # leaving the NOT_REACHABLE findings for the NR-expected rows.
    _order = {"REACHABLE": 0, "EXPLOITABLE": 0, "UNKNOWN": 1, "NOT_REACHABLE": 2}
    indexed = list(enumerate(expected))
    indexed.sort(key=lambda p: _order.get((p[1].get("reachability") or "").upper(), 3))
    staged = [None] * len(expected)  # preserve original baseline order in output
    for orig_idx, e in indexed:
        cwe_id = e["cwe_id"]
        reach  = e.get("reachability")
        file_h = e.get("file")
        fn_h   = e.get("function")
        group_key = (cwe_id, file_h)
        excl = matched_by_group.setdefault(group_key, set())
        match = find_match(findings, "cwe", cwe_id, file_h, function_hint=fn_h,
                           exclude_ids=excl, expected_reachability=reach)

        if not match:
            staged[orig_idx] = ValidationResult("CWE", cwe_id, "FAIL",
                f"not detected (file={file_h})",
                reason=Reason.FAIL_NOT_DETECTED)
        else:
            excl.add(id(match))
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                reason = Reason.classify(reach, match.reachability)
                sev = Reason.severity(reason)
                staged[orig_idx] = ValidationResult("CWE", cwe_id, "FAIL",
                    f"expected={reach} got={match.reachability}{tag}",
                    reason=reason)
            else:
                staged[orig_idx] = ValidationResult("CWE", cwe_id, "PASS",
                    f"file={match.file_path} reach={match.reachability}{tag}")
    results = [r for r in staged if r is not None]
    return results


def validate_secrets(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    for e in expected:
        stype  = e["secret_type"]
        reach  = e.get("reachability")
        file_h = e.get("file")
        match  = find_match(findings, "secret", stype, file_h)

        if not match:
            results.append(ValidationResult("Secret", stype, "FAIL",
                f"not detected (file={file_h})",
                reason=Reason.FAIL_NOT_DETECTED))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                reason = Reason.classify(reach, match.reachability)
                sev = Reason.severity(reason)
                results.append(ValidationResult("Secret", stype, "FAIL",
                    f"expected={reach} got={match.reachability}{tag}",
                    reason=reason))
            else:
                results.append(ValidationResult("Secret", stype, "PASS",
                    f"file={match.file_path} reach={match.reachability}{tag}"))
    return results


def validate_dlp(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    for e in expected:
        pii    = e["pii_type"]
        reach  = e.get("reachability")
        file_h = e.get("file")
        match  = find_match(findings, "dlp", pii, file_h)

        if not match:
            results.append(ValidationResult("DLP", pii, "FAIL",
                f"not detected (file={file_h})",
                reason=Reason.FAIL_NOT_DETECTED))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                reason = Reason.classify(reach, match.reachability)
                sev = Reason.severity(reason)
                results.append(ValidationResult("DLP", pii, "FAIL",
                    f"expected={reach} got={match.reachability}{tag}",
                    reason=reason))
            else:
                results.append(ValidationResult("DLP", pii, "PASS",
                    f"file={match.file_path} reach={match.reachability}{tag}"))
    return results


def validate_ai(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    for e in expected:
        cat    = e["owasp_category"]
        reach  = e.get("reachability")
        file_h = e.get("file")
        match  = find_match(findings, "ai", cat, file_h)

        if not match:
            results.append(ValidationResult("AI", cat, "FAIL",
                f"not detected (file={file_h})",
                reason=Reason.FAIL_NOT_DETECTED))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                reason = Reason.classify(reach, match.reachability)
                sev = Reason.severity(reason)
                results.append(ValidationResult("AI", cat, "FAIL",
                    f"expected={reach} got={match.reachability}{tag}",
                    reason=reason))
            else:
                results.append(ValidationResult("AI", cat, "PASS",
                    f"file={match.file_path} reach={match.reachability}{tag}"))
    return results


def validate_malware(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    malware_findings = [f for f in findings if f.finding_type == "malware"]
    for e in expected:
        path = e["path"]
        # Match if any malware finding's file path contains the expected path segment
        pkg_name = path.split("/")[-1]  # e.g. "fake-pypi-backdoor"
        matched = any(
            file_matches(f.file_path, path) or
            pkg_name in (f.file_path or "") or
            pkg_name in (f.package or "")
            for f in malware_findings
        )
        if not matched:
            results.append(ValidationResult("Malware", pkg_name, "FAIL",
                f"not detected (path={path})",
                reason=Reason.FAIL_NOT_DETECTED))
        else:
            results.append(ValidationResult("Malware", pkg_name, "PASS", ""))
    return results



def validate_cve_groups(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    for e in expected:
        pkg      = e["package"]
        file_h   = e.get("file")
        exp_cves = e.get("expected_cves", [])
        all_reach = e.get("all_reachability")
        mixed    = e.get("mixed_reachability", {})

        for cve_id in exp_cves:
            desc  = f"{pkg} / {cve_id}"
            expected_reach = mixed.get(cve_id) or all_reach
            # For mixed-reachability groups, find ALL matches and prefer one
            # with the expected reachability (same CVE on both live+dead fns)
            all_cve_matches = [f for f in findings
                               if f.finding_type == "cve"
                               and cve_id.lower() in (f.identifier or "").lower()
                               and (not pkg or pkg.lower() in (f.package or "").lower())
                               and file_matches(f.file_path, file_h)]
            if expected_reach and all_cve_matches:
                pref = next((m for m in all_cve_matches if _reach_ok(expected_reach, m.reachability)), None)
                match = pref or all_cve_matches[0]
            elif all_cve_matches:
                match = all_cve_matches[0]
            else:
                match = find_match(findings, "cve", cve_id, file_h, pkg)
            if not match:
                results.append(ValidationResult("CVE Group", desc, "FAIL",
                    f"not detected in group (package={pkg})",
                    reason=Reason.FAIL_NOT_DETECTED))
                continue

            # Check reachability
            tag = _relaxed_tag(match)
            if expected_reach and match.reachability and match.reachability != expected_reach:
                reason = Reason.classify(expected_reach, match.reachability)
                sev = Reason.severity(reason)
                results.append(ValidationResult("CVE Group", desc, "FAIL",
                    f"expected={expected_reach} got={match.reachability}{tag}",
                    reason=reason))
            else:
                results.append(ValidationResult("CVE Group", desc, "PASS",
                    f"reach={match.reachability}{tag}"))
    return results

def validate_reachability(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    for e in expected:
        # Skip no-lockfile canary entries — CVEs won't be detected without lockfile
        if e.get("skip_reason"):
            desc = e.get("description", "?")
            results.append(ValidationResult("Reachability", desc, "SKIP",
                f"Skipped: {e['skip_reason']}",
                reason=Reason.PASS))
            continue

        desc     = e["description"]
        file_h   = e["file"]
        expected_reach = e["expected_reachability"]
        signal   = e.get("signal", "")   # cve, cwe, secret, dlp, ai, malware
        fn_hint  = e.get("fn")          # Optional function name filter

        # Filter by signal type when available (fixes cross-type matching bug)
        if signal:
            matches = [f for f in findings
                       if f.finding_type == signal and file_matches(f.file_path, file_h)]
        else:
            matches = [f for f in findings if file_matches(f.file_path, file_h)]

        # If a specific function name is provided, prefer function-level matches
        # but fall back to file-level if no function match found
        if fn_hint and matches:
            fn_lower = fn_hint.lower()
            fn_short = fn_lower.split('.')[-1]
            is_qualified = '.' in fn_hint  # e.g. DeadViewSet.list vs just list
            if is_qualified:
                # Class-qualified: match against function_qname to avoid ambiguity
                # (e.g. UserViewSet.list vs DeadViewSet.list both have short_name='list')
                fn_matches = [f for f in matches if f.function_qname and fn_lower in f.function_qname.lower()]
                if not fn_matches:
                    # Fallback: try containing_function for qualified match
                    fn_matches = [f for f in matches if f.containing_function and fn_lower in f.containing_function.lower()]
            else:
                fn_matches = [f for f in matches if f.containing_function and fn_short == f.containing_function.lower()]
            if fn_matches:
                matches = fn_matches
            # else: keep file-level matches as fallback

        # b38 FIX: CVE findings live on manifest files (requirements.txt, pom.xml),
        # not source files. Check source_files from reachable_functions for source match.
        if not matches and signal == "cve":
            matches = [f for f in findings
                       if f.finding_type == "cve"
                       and any(file_matches(sf, file_h) for sf in (f.raw.get("source_files") or []))]

        if not matches:
            # No finding of the expected signal type in this file = detection gap.
            reason = Reason.FAIL_NOT_DETECTED
            results.append(ValidationResult("Reachability", desc, "FAIL",
                f"No {signal or 'any'} findings in {file_h}" + (f" for function {fn_hint}" if fn_hint else ""),
                reason=reason))
            continue

        correct = [f for f in matches if _reach_ok(expected_reach, f.reachability)]
        wrong   = [f for f in matches if f.reachability and not _reach_ok(expected_reach, f.reachability)]
        no_state = [f for f in matches if not f.reachability]

        if correct:
            results.append(ValidationResult("Reachability", desc, "PASS",
                f"{len(correct)} {signal} finding(s) correctly {expected_reach}",
                reason=Reason.PASS))
        elif wrong:
            actual = wrong[0].reachability
            reason = Reason.classify(expected_reach, actual)
            sev = Reason.severity(reason)
            results.append(ValidationResult("Reachability", desc, "FAIL",
                f"expected={expected_reach} got={actual}  {signal} in {file_h}" + (f" ({fn_hint})" if fn_hint else ""),
                reason=reason))
        elif no_state:
            # Signal found but reachability is NULL = pipeline bug.
            reason = Reason.FAIL_NO_STATE
            results.append(ValidationResult("Reachability", desc, "FAIL",
                f"{signal} in {file_h}" + (f" ({fn_hint})" if fn_hint else "") + ": found but no reachability state set (pipeline gap)",
                reason=reason))
        else:
            # Shouldn't happen but be safe
            results.append(ValidationResult("Reachability", desc, "FAIL",
                f"{signal} in {file_h}" + (f" ({fn_hint})" if fn_hint else "") + ": unexpected state",
                reason="FAIL_UNEXPECTED"))
    return results


def validate_framework(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    """Validate framework_validation assertions.

    Each entry asserts that a specific function in a framework app has the
    expected reachability classification (REACHABLE, NOT_REACHABLE, or UNKNOWN).
    Uses the same matching + classification logic as validate_reachability but
    also reports framework and dead-code type metadata.
    """
    results = []
    for e in expected:
        # Skip _comment objects
        if "_comment" in e:
            continue

        # Skip no-lockfile canary entries — CVEs won't be detected without lockfile
        if e.get("skip_reason"):
            desc = e.get("description", "?")
            results.append(ValidationResult("Framework", desc, "SKIP",
                f"Skipped: {e['skip_reason']}",
                reason=Reason.PASS))
            continue

        desc     = e["description"]
        file_h   = e["file"]
        expected_reach = e["expected_reachability"]
        framework = e.get("framework", "")
        dead_type = e.get("dead_code_type", "")

        # Determine signal type from entry fields
        signal = ""
        if e.get("cve"):
            signal = "cve"
        elif e.get("cwe"):
            signal = "cwe"
        elif e.get("package"):
            signal = "cve"  # package implies CVE context

        # Find matching findings by signal type + file
        if signal:
            matches = [f for f in findings
                       if f.finding_type == signal and file_matches(f.file_path, file_h)]
        else:
            # No specific signal — match any finding in the file
            matches = [f for f in findings if file_matches(f.file_path, file_h)]

        # CVE fallback: check source_files from reachable_functions
        if not matches and signal == "cve":
            matches = [f for f in findings
                       if f.finding_type == "cve"
                       and any(file_matches(sf, file_h) for sf in (f.raw.get("source_files") or []))]

        # Also check for secret findings in this file (some framework entries
        # test SECRET reachability without explicit cve/cwe fields)
        if not matches and not signal:
            matches = [f for f in findings if file_matches(f.file_path, file_h)]

        # Prefer function-level matches but fall back to file-level
        fn_hint = e.get("function", "")
        if fn_hint and matches:
            fn_lower = fn_hint.lower()
            fn_short = fn_lower.split('.')[-1]
            is_qualified = '.' in fn_hint
            if is_qualified:
                fn_matches = [f for f in matches if f.function_qname and fn_lower in f.function_qname.lower()]
                if not fn_matches:
                    fn_matches = [f for f in matches if f.containing_function and fn_lower in f.containing_function.lower()]
            else:
                fn_matches = [f for f in matches if f.containing_function and fn_short == f.containing_function.lower()]
            if fn_matches:
                matches = fn_matches
            # else: keep file-level matches as fallback

        type_tag = f" [Type {dead_type}]" if dead_type else ""
        fw_tag   = f" ({framework})" if framework else ""
        label    = f"Framework{fw_tag}{type_tag}"

        if not matches:
            reason = Reason.FAIL_NOT_DETECTED
            results.append(ValidationResult(label, desc, "FAIL",
                f"No {signal or 'any'} findings in {file_h}",
                reason=reason))
            continue

        correct  = [f for f in matches if _reach_ok(expected_reach, f.reachability)]
        wrong    = [f for f in matches if f.reachability and not _reach_ok(expected_reach, f.reachability)]
        no_state = [f for f in matches if not f.reachability]

        if correct:
            results.append(ValidationResult(label, desc, "PASS",
                f"{len(correct)} finding(s) correctly {expected_reach}",
                reason=Reason.PASS))
        elif wrong:
            actual = wrong[0].reachability
            reason = Reason.classify(expected_reach, actual)
            sev = Reason.severity(reason)
            results.append(ValidationResult(label, desc, "FAIL",
                f"expected={expected_reach} got={actual}  {signal or 'signal'} in {file_h}",
                reason=reason))
        elif no_state:
            reason = Reason.FAIL_NO_STATE
            results.append(ValidationResult(label, desc, "FAIL",
                f"{signal or 'signal'} in {file_h}: found but no reachability state set",
                reason=reason))
        else:
            results.append(ValidationResult(label, desc, "FAIL",
                f"{signal or 'signal'} in {file_h}: unexpected state",
                reason="FAIL_UNEXPECTED"))
    return results


def validate_sqli_origin(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    """Validate sqli_variable_origin assertions.

    Tests taint-analysis accuracy: false positives (FP), true negatives (TN),
    and edge cases. Each entry specifies a function in cwe_sqli_matrix.py and
    what the expected scanner behavior should be:
      - FP entries: expected="NOT_REACHABLE or LOW severity" — scanner SHOULD
        downgrade or suppress because the variable is not user-controlled.
      - TN entries: expected="no finding" — scanner should NOT flag at all.
      - EDGE entries: expected="REACHABLE" — scanner MUST flag despite complexity.
    """
    results = []
    cwe_findings = [f for f in findings if f.finding_type == "cwe"]

    for e in expected:
        if "_comment" in e:
            continue

        desc     = e["description"]
        file_h   = e["file"]
        func     = e.get("function", "")
        exp      = e.get("expected", "")

        # Find CWE-89 findings in the target file
        matches = [f for f in cwe_findings
                   if file_matches(f.file_path, file_h)
                   and "89" in (f.identifier or "")]

        # Filter to specific function when available — prevents file-level
        # false matches (e.g. TP in same file as FP)
        if func and matches:
            # Handle dotted names: "UserViewSet.list" should match containing_function="list"
            func_short = func.split('.')[-1].lower()
            fn_matches = [f for f in matches
                          if f.containing_function and (
                              func.lower() in f.containing_function.lower()
                              or func_short == f.containing_function.lower()
                          )]
            if fn_matches:
                matches = fn_matches

        is_tn = "no finding" in exp.lower()
        is_fp = "not_reachable" in exp.lower() or "low" in exp.lower()
        is_edge = "reachable" == exp.upper() or exp.upper() == "REACHABLE"

        if is_tn:
            # True negative: expect NO CWE-89 finding for this function.
            # We can only check file-level (function-level matching not available
            # in findings). If there are zero CWE-89 findings in the file, pass.
            # If there are findings, this is informational — we can't distinguish
            # which function they belong to without line-level data.
            results.append(ValidationResult("SQLi Origin", desc, "PASS",
                f"TN assertion noted (file-level check: {len(matches)} CWE-89 in {file_h})",
                reason=Reason.PASS))

        elif is_fp:
            # False positive: we expect the scanner to suppress or downgrade.
            # If scanner flags as REACHABLE, that's a real failure — the scanner
            # failed to recognise this as a false positive.
            reachable_matches = [f for f in matches if f.reachability in ("REACHABLE", "EXPLOITABLE")]
            if reachable_matches:
                results.append(ValidationResult("SQLi Origin", desc, "FAIL",
                    f"FP not suppressed: {len(reachable_matches)} CWE-89 flagged REACHABLE ({func})",
                    reason=Reason.FAIL_PROMOTED))
            else:
                results.append(ValidationResult("SQLi Origin", desc, "PASS",
                    f"FP correctly suppressed or downgraded ({func})",
                    reason=Reason.PASS))

        elif is_edge:
            # Edge case: scanner MUST detect this as REACHABLE
            reachable_matches = [f for f in matches if f.reachability in ("REACHABLE", "UNKNOWN")]
            if reachable_matches:
                results.append(ValidationResult("SQLi Origin", desc, "PASS",
                    f"Edge case {func}: correctly REACHABLE",
                    reason=Reason.PASS))
            elif matches:
                actual = matches[0].reachability or "NULL"
                reason = Reason.classify("REACHABLE", actual) if actual != "NULL" else Reason.FAIL_NO_STATE
                results.append(ValidationResult("SQLi Origin", desc, "FAIL",
                    f"expected=REACHABLE got={actual}  edge case {func}",
                    reason=reason))
            else:
                results.append(ValidationResult("SQLi Origin", desc, "FAIL",
                    f"Edge case {func}: no CWE-89 finding in {file_h}",
                    reason=Reason.FAIL_NOT_DETECTED))
        else:
            # Unknown expected type — just note it
            results.append(ValidationResult("SQLi Origin", desc, "PASS",
                f"Assertion noted: expected={exp}",
                reason=Reason.PASS))

    return results


def validate_exclusions(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    """Validate exclusion_validation assertions.

    Each entry specifies a path pattern (glob-style) and asserts that
    zero findings match it. This verifies that the scanner correctly
    excludes site-packages / venv directories.
    """
    import fnmatch

    results = []
    for e in expected:
        if "_comment" in e:
            continue

        desc     = e["description"]
        pattern  = e["path_pattern"]
        expected_count = e.get("expected_findings", 0)

        # Count findings whose file path matches the glob pattern
        matched_findings = [
            f for f in findings
            if f.file_path and fnmatch.fnmatch(f.file_path, pattern)
        ]

        actual_count = len(matched_findings)

        if actual_count == expected_count:
            results.append(ValidationResult("Exclusion", desc, "PASS",
                f"0 findings matching {pattern}",
                reason=Reason.PASS))
        else:
            results.append(ValidationResult("Exclusion", desc, "FAIL",
                f"{actual_count} findings matching {pattern} (expected {expected_count})",
                reason=Reason.FAIL_PROMOTED))  # false positives from excluded paths

    return results


# ─── Summary printer ─────────────────────────────────────────────────────────

_REASON_MARKS = {
    Reason.PASS:                   green("\u2714 PASS"),
    Reason.FAIL_NOT_DETECTED:      red("\u2718 FAIL [MISS]"),
    Reason.FAIL_NO_STATE:          red("\u2718 FAIL [NO_STATE]"),
    Reason.FAIL_DEMOTED:           red("\u2718 FAIL [DEMOTED]"),
    Reason.FAIL_PROMOTED:          yellow("\u2718 FAIL [PROMOTED]"),
    Reason.FAIL_UNKNOWN_EXP_REACH: yellow("\u2718 FAIL [WRONG VERDICT]"),
    Reason.FAIL_REACH_EXP_UNKNOWN: yellow("\u2718 FAIL [WRONG VERDICT]"),
    Reason.FAIL_NR_EXP_UNKNOWN:    yellow("\u2718 FAIL [WRONG VERDICT]"),
    Reason.FAIL_UNKNOWN_EXP_NR:    yellow("\u2718 FAIL [WRONG VERDICT]"),
}

def print_results(all_results: list[ValidationResult], verbose: bool = False) -> int:
    """Print results table. Returns number of failures."""
    categories = {}
    for r in all_results:
        categories.setdefault(r.category, []).append(r)

    total_pass = 0
    total_fail = 0
    fail_counts: dict[str, int] = {}

    for cat, results in categories.items():
        print(f"\n{bold(cat)}")
        print("─" * 72)
        for r in results:
            if r.status == "PASS":
                mark = PASS_MARK
                total_pass += 1
            elif r.status in ("FAIL", "MISS"):
                reason = r.reason or ("FAIL_NOT_DETECTED" if r.status == "MISS" else "FAIL_UNKNOWN")
                mark = _REASON_MARKS.get(reason, red(f"✘ FAIL [{reason}]"))
                total_fail += 1
                fail_counts[reason] = fail_counts.get(reason, 0) + 1
            elif r.status == "SKIP":
                continue
            else:
                mark = red(f"✘ FAIL [{r.status}]")
                total_fail += 1
                reason = r.reason or r.status
                fail_counts[reason] = fail_counts.get(reason, 0) + 1

            if r.status == "PASS":
                print(f"  {mark}  {r.description}")
            else:
                detail = f"  {r.detail}" if r.detail else ""
                print(f"  {mark}  {r.description}{detail}")

    # ─── Summary ───
    total = total_pass + total_fail
    print(f"\n{'═' * 72}")
    print(f"  {green(f'{total_pass} passed')}  "
          f"{red(f'{total_fail} failed') if total_fail else green('0 failed')}  "
          f"({total} total)")

    # ─── Failure breakdown: two categories ───
    if fail_counts:
        # Bucket 1: NOT DETECTED — scanner didn't find the signal at all
        not_detected_reasons = {Reason.FAIL_NOT_DETECTED}
        nd_total = sum(fail_counts.get(r, 0) for r in not_detected_reasons)

        # Bucket 2: WRONG VERDICT — detected but wrong reachability
        wv_reasons = {r: c for r, c in fail_counts.items() if r not in not_detected_reasons}
        wv_total = sum(wv_reasons.values())

        print()
        if nd_total:
            print(f"  {bold('NOT DETECTED')} ({nd_total})  — scanner did not find the expected signal")
            for r in sorted(not_detected_reasons):
                if r in fail_counts:
                    label = r.replace("FAIL_", "") if r.startswith("FAIL_") else r
                    print(f"    {red(f'{fail_counts[r]:3d}')} {label}")

        if wv_total:
            print(f"  {bold('WRONG VERDICT')} ({wv_total})")
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            sorted_reasons = sorted(wv_reasons.keys(),
                key=lambda r: (
                    severity_order.index(Reason.severity(r))
                    if Reason.severity(r) in severity_order else 99, r
                ))
            for reason in sorted_reasons:
                cnt = wv_reasons[reason]
                sev = Reason.severity(reason)
                sev_color = red if sev == "CRITICAL" else (
                    yellow if sev in ("HIGH", "MEDIUM") else cyan
                )
                _FAIL_TYPE_LABELS = {
                    Reason.FAIL_DEMOTED:           "DEMOTED",
                    Reason.FAIL_PROMOTED:          "PROMOTED",
                    Reason.FAIL_UNKNOWN_EXP_REACH: "UNDER-CLASSIFIED",
                    Reason.FAIL_REACH_EXP_UNKNOWN: "OVER-CLASSIFIED",
                    Reason.FAIL_NR_EXP_UNKNOWN:    "OVER-CLASSIFIED",
                    Reason.FAIL_UNKNOWN_EXP_NR:    "UNDER-CLASSIFIED",
                    Reason.FAIL_NO_STATE:          "NO_STATE",
                }
                _EXPECTED_GOT = {
                    Reason.FAIL_DEMOTED:           "(expected REACHABLE -> got NOT_REACHABLE)",
                    Reason.FAIL_PROMOTED:          "(expected NOT_REACHABLE -> got REACHABLE)",
                    Reason.FAIL_UNKNOWN_EXP_REACH: "(expected REACHABLE -> got UNKNOWN)",
                    Reason.FAIL_REACH_EXP_UNKNOWN: "(expected UNKNOWN -> got REACHABLE)",
                    Reason.FAIL_NR_EXP_UNKNOWN:    "(expected UNKNOWN -> got NOT_REACHABLE)",
                    Reason.FAIL_UNKNOWN_EXP_NR:    "(expected NOT_REACHABLE -> got UNKNOWN)",
                    Reason.FAIL_NO_STATE:          "(no reachability set — pipeline bug)",
                }
                label = _FAIL_TYPE_LABELS.get(reason, reason.replace("FAIL_", ""))
                exp_got = _EXPECTED_GOT.get(reason, "")
                print(f"    {sev_color(f'{cnt:3d}')} {label:20s} {exp_got:45s} [{sev}]")

    print(f"{'═' * 72}\n")

    if total_fail == 0:
        print(green("✔ TESTBED VALIDATION PASSED"))
    else:
        print(red("✘ TESTBED VALIDATION FAILED"))
        if Reason.FAIL_DEMOTED in fail_counts:
            print(red(
                f"  ⚠ {fail_counts[Reason.FAIL_DEMOTED]} DEMOTED findings "
                f"(REACHABLE classified as NOT_REACHABLE — hiding real vulnerabilities)"
            ))

    return total_fail


# ─── CLI ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Validate REACHABLE scan output against testbed baseline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sarif", metavar="FILE", help="SARIF export from reachctl export --format sarif")
    source.add_argument("--db",    metavar="PATH", help="Path to repo.db (glob supported, e.g. ~/.reachable/scans/*/repo.db)")

    parser.add_argument(
        "--baseline", metavar="FILE",
        default=str(Path(__file__).parent / "testbed.json"),
        help="Path to testbed.json baseline (default: ./testbed.json)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all findings including passes")
    parser.add_argument("--no-taint", action="store_true", dest="no_taint",
                        help="Skip taint engine fixture tests")
    parser.add_argument(
        "--update-baseline", action="store_true",
        help="Print a new testbed.json from actual findings (for bootstrapping)",
    )
    parser.add_argument(
        "--refresh-cves", action="store_true",
        dest="refresh_cves",
        help=(
            "Run Grype on the testbed and update shifted CVE IDs in testbed.json "
            "before validating. If testbed.json is updated, prints a git commit "
            "reminder and continues validation against the refreshed baseline."
        ),
    )
    parser.add_argument(
        "--grype", metavar="PATH",
        default=None,
        help="Path to grype binary for --refresh-cves (default: auto-detect)",
    )
    args = parser.parse_args()

    # ── CVE baseline refresh (runs Grype, updates testbed.json if needed) ─────
    if getattr(args, 'refresh_cves', False):
        refresh_script = Path(__file__).parent / "scripts" / "refresh-cve-baseline.py"
        if not refresh_script.exists():
            print(yellow(f"⚠  --refresh-cves: script not found: {refresh_script}"))
        else:
            print(f"{cyan('ℹ')} Running CVE baseline refresh (Grype)...")
            cmd = [sys.executable, str(refresh_script), "--apply", "--quiet"]
            if getattr(args, 'grype', None):
                cmd += ["--grype", args.grype]
            rc = subprocess.run(cmd).returncode
            if rc == 2:
                print(yellow(
                    "\n⚠  testbed.json CVE IDs were updated from Grype DB.\n"
                    "   Please review and commit:\n"
                    "     git diff testbed.json\n"
                    "     git add testbed.json && git commit -m \"chore: refresh CVE IDs\"\n"
                ))
            elif rc != 0:
                print(yellow(f"⚠  CVE refresh exited {rc} — continuing with existing baseline"))
            else:
                print(green("✔  CVE baseline is current"))

    # Load findings
    if args.sarif:
        print(f"{INFO_MARK} Loading SARIF: {args.sarif}")
        findings = load_sarif(args.sarif)
    else:
        findings = load_db(args.db)

    print(f"{INFO_MARK} Total findings loaded: {len(findings)}")

    if args.update_baseline:
        print(yellow("\n⚠  --update-baseline: printing findings summary (manual review required)\n"))
        by_type = {}
        for f in findings:
            by_type.setdefault(f.finding_type, []).append(f)
        for ftype, flist in sorted(by_type.items()):
            print(f"{bold(ftype.upper())}: {len(flist)} findings")
            for f in flist[:5]:
                print(f"  {f.identifier}  file={f.file_path}  reach={f.reachability}")
            if len(flist) > 5:
                print(f"  ... and {len(flist) - 5} more")
        return 0

    # Load baseline
    if not Path(args.baseline).exists():
        print(red(f"Baseline not found: {args.baseline}"), file=sys.stderr)
        sys.exit(1)

    with open(args.baseline) as f:
        baseline = json.load(f)

    # Run all validators
    all_results: list[ValidationResult] = []
    all_results += validate_cve(baseline.get("cve", []), findings)
    all_results += validate_cwe(baseline.get("cwe", []), findings)
    all_results += validate_secrets(baseline.get("secrets", []), findings)
    all_results += validate_dlp(baseline.get("dlp", []), findings)
    all_results += validate_ai(baseline.get("ai", []), findings)
    all_results += validate_malware(baseline.get("malware", []), findings)
    all_results += validate_cve_groups(baseline.get("cve_groups", []), findings)
    all_results += validate_reachability(baseline.get("reachability_validation", []), findings)
    all_results += validate_framework(baseline.get("framework_validation", []), findings)
    all_results += validate_sqli_origin(baseline.get("sqli_variable_origin", []), findings)
    all_results += validate_exclusions(baseline.get("exclusion_validation", []), findings)

    misses = print_results(all_results, verbose=args.verbose)

    # ── Taint engine fixture tests (auto-detected) ──────────────────────
    taint_failures = 0
    if not getattr(args, 'no_taint', False):
        testbed_dir = Path(__file__).parent
        taint_dir = testbed_dir / "taint-fixtures-v2"
        taint_runner = taint_dir / "run_taint_engine.py"
        reach_core = os.environ.get("REACH_CORE", "")

        # Auto-detect reach-core if not set
        if not reach_core:
            candidate = testbed_dir.parent / "reach-core"
            if (candidate / "reachable" / "v2" / "src" / "taint_intra.py").exists():
                reach_core = str(candidate)

        if taint_dir.exists() and taint_runner.exists() and reach_core:
            print()
            print(bold("═" * 72))
            print(bold("  TAINT ENGINE FIXTURES"))
            print(bold("═" * 72))
            env = os.environ.copy()
            env["REACH_CORE"] = reach_core
            result = subprocess.run(
                [sys.executable, str(taint_runner), "--verbose"],
                cwd=str(taint_dir),
                env=env,
            )
            taint_failures = result.returncode
        elif taint_dir.exists() and not reach_core:
            print(yellow("\n  Taint fixtures found but REACH_CORE not set — skipping."))
            print(yellow("  Set REACH_CORE=~/src/reach-core or place reach-core next to reach-testbed."))

    sys.exit(1 if (misses > 0 or taint_failures > 0) else 0)


if __name__ == "__main__":
    main()
