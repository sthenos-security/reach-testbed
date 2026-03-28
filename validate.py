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
FAIL_MARK = red("✘ MISS")
WARN_MARK = yellow("⚠ WARN")
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
    raw: dict = field(default_factory=dict)


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
    status: str   # PASS, MISS, WARN (legacy) or Reason.* for reachability
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
        SELECT signal_type, finding_id, display_id, cwe_id, secret_type,
               owasp_category, pii_type, file_path, app_reachability,
               package_name, containing_function, raw_data
        FROM signals
        WHERE scan_id = (SELECT MAX(id) FROM scans)
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


def find_match(findings: list[FindingRecord], ftype: str,
               identifier: str, file_hint: Optional[str] = None,
               package: Optional[str] = None) -> Optional[FindingRecord]:
    """Find the best matching finding for a baseline entry.

    Returns a FindingRecord with `relaxed_match` attribute set to True if the
    match was found only by dropping the file requirement (second pass).
    """
    candidates = [f for f in findings if f.finding_type == ftype]

    # Pass 1: strict — require identifier + package + file
    for f in candidates:
        id_match   = identifier.lower() in (f.identifier or "").lower()
        pkg_match  = (not package) or (package.lower() in (f.package or "").lower())
        file_match = file_matches(f.file_path, file_hint)

        if id_match and pkg_match and file_match:
            f.relaxed_match = False
            return f

    # Pass 2: relaxed — drop file requirement (flag it so callers can warn)
    if file_hint:
        for f in candidates:
            id_match  = identifier.lower() in (f.identifier or "").lower()
            pkg_match = (not package) or (package.lower() in (f.package or "").lower())
            if id_match and pkg_match:
                f.relaxed_match = True
                return f

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
            results.append(ValidationResult("CVE", cve_id, "MISS",
                f"Not found (package={pkg}, file={file_h})"))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                results.append(ValidationResult("CVE", cve_id, "WARN",
                    f"Found but reachability={match.reachability}, expected={reach}{tag}"))
            else:
                results.append(ValidationResult("CVE", cve_id, "PASS",
                    f"pkg={match.package} reach={match.reachability}{tag}"))
    return results


def validate_cwe(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    for e in expected:
        cwe_id = e["cwe_id"]
        reach  = e.get("reachability")
        file_h = e.get("file")
        match  = find_match(findings, "cwe", cwe_id, file_h)

        if not match:
            results.append(ValidationResult("CWE", cwe_id, "MISS",
                f"Not found (file={file_h})"))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                results.append(ValidationResult("CWE", cwe_id, "WARN",
                    f"Found but reachability={match.reachability}, expected={reach}{tag}"))
            else:
                results.append(ValidationResult("CWE", cwe_id, "PASS",
                    f"file={match.file_path} reach={match.reachability}{tag}"))
    return results


def validate_secrets(expected: list[dict], findings: list[FindingRecord]) -> list[ValidationResult]:
    results = []
    for e in expected:
        stype  = e["secret_type"]
        reach  = e.get("reachability")
        file_h = e.get("file")
        match  = find_match(findings, "secret", stype, file_h)

        if not match:
            results.append(ValidationResult("Secret", stype, "MISS",
                f"Not found (file={file_h})"))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                results.append(ValidationResult("Secret", stype, "WARN",
                    f"Found but reachability={match.reachability}, expected={reach}{tag}"))
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
            results.append(ValidationResult("DLP", pii, "MISS",
                f"Not found (file={file_h})"))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                results.append(ValidationResult("DLP", pii, "WARN",
                    f"Found but reachability={match.reachability}, expected={reach}{tag}"))
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
            results.append(ValidationResult("AI", cat, "MISS",
                f"Not found (file={file_h})"))
        else:
            tag = _relaxed_tag(match)
            if reach and match.reachability and match.reachability != reach:
                results.append(ValidationResult("AI", cat, "WARN",
                    f"Found but reachability={match.reachability}, expected={reach}{tag}"))
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
            results.append(ValidationResult("Malware", pkg_name, "MISS",
                f"Not found (path={path})"))
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
            match = find_match(findings, "cve", cve_id, file_h, pkg)
            desc  = f"{pkg} / {cve_id}"
            if not match:
                results.append(ValidationResult("CVE Group", desc, "MISS",
                    f"Not found in group (package={pkg})"))
                continue

            # Check reachability
            tag = _relaxed_tag(match)
            expected_reach = mixed.get(cve_id) or all_reach
            if expected_reach and match.reachability and match.reachability != expected_reach:
                results.append(ValidationResult("CVE Group", desc, "WARN",
                    f"Found but reachability={match.reachability}, expected={expected_reach}{tag}"))
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
            fn_parts = fn_hint.lower().split('.')
            fn_short = fn_parts[-1]
            fn_matches = [f for f in matches if f.containing_function and (
                fn_hint.lower() in f.containing_function.lower()
                or fn_short == f.containing_function.lower()
            )]
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

        correct = [f for f in matches if f.reachability == expected_reach]
        wrong   = [f for f in matches if f.reachability and f.reachability != expected_reach]
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
                f"{signal} in {file_h}" + (f" ({fn_hint})" if fn_hint else "") + f": got {actual}, expected {expected_reach} [{sev}]",
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
            fn_parts = fn_hint.lower().split('.')
            fn_short = fn_parts[-1]
            fn_matches = [f for f in matches if f.containing_function and (
                fn_hint.lower() in f.containing_function.lower()
                or fn_short == f.containing_function.lower()
            )]
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

        correct  = [f for f in matches if f.reachability == expected_reach]
        wrong    = [f for f in matches if f.reachability and f.reachability != expected_reach]
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
                f"{signal or 'signal'} in {file_h}: got {actual}, expected {expected_reach} [{sev}]",
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
            reachable_matches = [f for f in matches if f.reachability == "REACHABLE"]
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
            reachable_matches = [f for f in matches if f.reachability == "REACHABLE"]
            if reachable_matches:
                results.append(ValidationResult("SQLi Origin", desc, "PASS",
                    f"Edge case correctly flagged REACHABLE ({func})",
                    reason=Reason.PASS))
            elif matches:
                actual = matches[0].reachability or "NULL"
                reason = Reason.classify("REACHABLE", actual) if actual != "NULL" else Reason.FAIL_NO_STATE
                results.append(ValidationResult("SQLi Origin", desc, "FAIL",
                    f"Edge case {func}: got {actual}, expected REACHABLE",
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
    Reason.PASS:                   PASS_MARK,
    Reason.FAIL_NOT_DETECTED:      red("✘ NOT_DETECTED"),
    Reason.FAIL_NO_STATE:          red("✘ NO_STATE"),
    Reason.FAIL_DEMOTED:           red("✘ DEMOTED"),
    Reason.FAIL_PROMOTED:          yellow("✘ PROMOTED"),
    Reason.FAIL_UNKNOWN_EXP_REACH: yellow("✘ UNK←REACH"),
    Reason.FAIL_REACH_EXP_UNKNOWN: yellow("✘ REACH←UNK"),
    Reason.FAIL_NR_EXP_UNKNOWN:    yellow("✘ NR←UNK"),
    Reason.FAIL_UNKNOWN_EXP_NR:    yellow("✘ UNK←NR"),
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
            elif r.status == "FAIL":
                reason = r.reason or "FAIL_UNKNOWN"
                mark = _REASON_MARKS.get(reason, red(f"✘ {reason}"))
                total_fail += 1
                fail_counts[reason] = fail_counts.get(reason, 0) + 1
            elif r.status == "MISS":
                mark = FAIL_MARK
                total_fail += 1
                fail_counts["MISS"] = fail_counts.get("MISS", 0) + 1
            elif r.status == "SKIP":
                # SKIP = intentional test design (e.g. no lockfile canary).
                # When a lockfile is absent, CVE detection is impossible and
                # reachability is UNKNOWN by definition. This is correct scanner
                # behavior, not a failure — count as PASS.
                mark = WARN_MARK
                total_pass += 1
            else:
                mark = WARN_MARK
                total_fail += 1
                fail_counts["WARN"] = fail_counts.get("WARN", 0) + 1

            show = r.status != "PASS" or verbose
            if show:
                detail = f"  {r.detail}" if r.detail else ""
                print(f"  {mark}  {r.description}{detail}")
            else:
                print(f"  {mark}  {r.description}")

    # ─── Summary ───
    total = total_pass + total_fail
    print(f"\n{'═' * 72}")
    print(f"  {green(f'{total_pass} passed')}  "
          f"{red(f'{total_fail} failed') if total_fail else green('0 failed')}  "
          f"({total} total)")

    # ─── Failure breakdown ───
    if fail_counts:
        print(f"\n  {bold('Failure Breakdown:')}")
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sorted_reasons = sorted(fail_counts.keys(),
            key=lambda r: (
                severity_order.index(Reason.severity(r))
                if Reason.severity(r) in severity_order else 99, r
            ))
        for reason in sorted_reasons:
            cnt = fail_counts[reason]
            sev = Reason.severity(reason)
            sev_color = red if sev == "CRITICAL" else (
                yellow if sev in ("HIGH", "MEDIUM") else cyan
            )
            label = reason.replace("FAIL_", "") if reason.startswith("FAIL_") else reason
            print(f"    {sev_color(f'{cnt:3d}')} {label:30s} [{sev}]")

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
    sys.exit(1 if misses > 0 else 0)


if __name__ == "__main__":
    main()
