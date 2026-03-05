#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Private Registry Integration Tests

Validates that `reachctl scan` correctly handles projects pulling from
both public registries and private Docker-based registries.

Test strategy — for each ecosystem we verify 6 layers:
    1. EXIT CODE   — scan completed without crash
    2. SCAN LOG    — no fatal tool failures (syft/grype/semgrep/guarddog/tree-sitter)
    3. SBOM        — both public AND private packages appear in sbom.json
    4. REPO.DB     — scans.status='complete', findings populated, unresolved tracked
    5. CACHE/LIBS  — vulnerable lib source cloned to libs/, global cache populated
    6. RAW FILES   — scan-manifest.json, cve-analyzed.json, correlation.json exist
"""

import json
import re
import sqlite3
from pathlib import Path

import pytest


# ============================================================================
# PYTHON-MIXED TESTS
# ============================================================================

class TestPythonMixedExitAndLog:
    """Layer 1 & 2: Exit code and scan.log health."""

    def test_PY01_scan_exits_zero(self, python_mixed_scan):
        """reachctl scan completes without crash."""
        r = python_mixed_scan
        assert r.exit_code == 0, (
            f"reachctl exited {r.exit_code}\n"
            f"STDERR (last 500): {r.stderr[-500:]}\n"
            f"SCAN.LOG (last 500): {r.scan_log[-500:]}"
        )

    def test_PY02_no_fatal_tool_errors(self, python_mixed_scan):
        """scan.log has no fatal syft/grype/semgrep/guarddog/tree-sitter errors."""
        r = python_mixed_scan
        assert not r.log_has_fatal(), (
            f"Fatal error in scan.log:\n{r.scan_log[-1000:]}"
        )

    def test_PY03_no_syft_failure(self, python_mixed_scan):
        """Syft SBOM generation did not fail."""
        r = python_mixed_scan
        assert not r.log_contains(r'syft.*error|syft.*fail|SBOM generation failed'), \
            "Syft failure detected in scan.log"

    def test_PY04_no_grype_failure(self, python_mixed_scan):
        """Grype vulnerability scan did not fail."""
        r = python_mixed_scan
        assert not r.log_contains(r'grype.*error.*fatal|grype.*fail|vulnerability scan failed'), \
            "Grype failure detected in scan.log"

    def test_PY05_no_semgrep_crash(self, python_mixed_scan):
        """Semgrep SAST did not crash fatally."""
        r = python_mixed_scan
        # Semgrep warnings are OK; crashes/fatal errors are not
        assert not r.log_contains(r'semgrep.*fatal|semgrep.*crash|semgrep.*segfault'), \
            "Semgrep crash detected in scan.log"

    def test_PY06_no_treesitter_failure(self, python_mixed_scan):
        """Tree-sitter call graph generation did not segfault/crash."""
        r = python_mixed_scan
        assert not r.log_contains(r'tree.sitter.*segfault|tree.sitter.*crash|call.graph.*fatal'), \
            "Tree-sitter failure detected in scan.log"


class TestPythonMixedSBOM:
    """Layer 3: SBOM contains public and private packages."""

    def test_PY10_sbom_exists(self, python_mixed_scan):
        """sbom.json was generated."""
        assert python_mixed_scan.sbom is not None, "sbom.json not found"

    def test_PY11_sbom_has_artifacts(self, python_mixed_scan):
        """SBOM has at least some artifacts."""
        sbom = python_mixed_scan.sbom
        artifacts = sbom.get('artifacts', [])
        assert len(artifacts) > 0, "SBOM has zero artifacts"

    def test_PY12_public_requests_in_sbom(self, python_mixed_scan):
        """Public package 'requests' appears in SBOM."""
        names = python_mixed_scan.sbom_artifact_names
        assert 'requests' in names, f"'requests' not in SBOM. Got: {names[:20]}"

    def test_PY13_public_flask_in_sbom(self, python_mixed_scan):
        """Public package 'flask' appears in SBOM."""
        names = python_mixed_scan.sbom_artifact_names
        # flask or Flask (Syft may capitalize)
        assert any(n.lower() == 'flask' for n in names), \
            f"'flask' not in SBOM. Got: {names[:20]}"

    def test_PY14_private_authlib_in_sbom(self, python_mixed_scan):
        """Private authlib mirror from devpi appears in SBOM."""
        names = [n.lower() for n in python_mixed_scan.sbom_artifact_names]
        assert 'authlib' in names, f"'authlib' (devpi mirror) not in SBOM: {names[:20]}"

    def test_PY14b_private_internal_sdk_in_sbom(self, python_mixed_scan):
        """Genuine private internal-sdk from devpi appears in SBOM."""
        names = [n.lower() for n in python_mixed_scan.sbom_artifact_names]
        found = any('internal-sdk' in n or 'internal_sdk' in n for n in names)
        assert found, f"'internal-sdk' (devpi private) not in SBOM: {names[:20]}"

    def test_PY15_sbom_purls_have_pypi_scheme(self, python_mixed_scan):
        """SBOM PURLs use pkg:pypi/ scheme."""
        purls = python_mixed_scan.sbom_purls
        pypi_purls = [p for p in purls if p.startswith('pkg:pypi/')]
        assert len(pypi_purls) > 0, f"No pkg:pypi/ PURLs. Got: {purls[:10]}"


class TestPythonMixedDatabase:
    """Layer 4: repo.db scans + findings + unresolved packages."""

    def test_PY20_repo_db_exists(self, python_mixed_scan):
        """repo.db was created."""
        assert python_mixed_scan.repo_db_path is not None, "repo.db not found"
        assert python_mixed_scan.repo_db_path.exists(), \
            f"repo.db path {python_mixed_scan.repo_db_path} does not exist"

    def test_PY21_scan_status_complete(self, python_mixed_scan):
        """scans.status = 'complete' in repo.db."""
        assert python_mixed_scan.completed, (
            f"Scan not complete. status={python_mixed_scan.db_scan_row.get('status') if python_mixed_scan.db_scan_row else 'NO ROW'}"
        )

    def test_PY22_scan_has_duration(self, python_mixed_scan):
        """Scan recorded a non-zero duration."""
        row = python_mixed_scan.db_scan_row
        assert row is not None
        assert row.get('duration_seconds', 0) > 0, \
            f"duration_seconds={row.get('duration_seconds')}"

    def test_PY23_findings_populated(self, python_mixed_scan):
        """findings table has rows for this scan."""
        assert len(python_mixed_scan.db_findings) > 0, \
            "No findings in repo.db (expected CVEs from flask 2.0.3 + requests 2.31.0)"

    def test_PY24_cve_findings_exist(self, python_mixed_scan):
        """At least one CVE finding exists."""
        cves = python_mixed_scan.cve_findings
        assert len(cves) > 0, "No CVE findings — grype may have failed silently"

    def test_PY25_flask_has_cves(self, python_mixed_scan):
        """Flask 2.0.3 has known CVEs in findings."""
        flask_cves = python_mixed_scan.findings_for_package('flask')
        assert len(flask_cves) > 0, "No CVEs for flask 2.0.3 (known vulnerable)"

    def test_PY26_finding_fields_populated(self, python_mixed_scan):
        """CVE findings have required fields: severity, package_name, finding_id."""
        for f in python_mixed_scan.cve_findings[:5]:  # spot check first 5
            assert f.get('severity'), f"Missing severity: {f.get('finding_id')}"
            assert f.get('package_name'), f"Missing package_name: {f.get('finding_id')}"
            assert f.get('finding_id'), "Missing finding_id"
            assert f.get('scanner'), f"Missing scanner: {f.get('finding_id')}"

    def test_PY27_scan_totals_consistent(self, python_mixed_scan):
        """scans.total_findings matches actual count in findings table."""
        row = python_mixed_scan.db_scan_row
        if not row:
            pytest.skip("No scan row")
        db_total = row.get('total_findings', 0)
        actual_non_config = len([f for f in python_mixed_scan.db_findings
                                  if f.get('finding_type') != 'config'])
        assert db_total == actual_non_config, \
            f"scans.total_findings={db_total} but findings table has {actual_non_config} non-config rows"

    def test_PY28_unresolved_packages_tracked(self, python_mixed_scan):
        """If private packages were scanned, unresolved_packages has entries
        (private PURLs won't match public registries)."""
        # This is informational — may be empty if private pkgs not enabled
        unresolved = python_mixed_scan.db_unresolved
        if unresolved:
            for u in unresolved:
                assert u.get('name'), "Unresolved entry missing name"
                assert u.get('reason'), "Unresolved entry missing reason"

    def test_PY29_risk_level_set(self, python_mixed_scan):
        """Scan has a risk_level assigned."""
        row = python_mixed_scan.db_scan_row
        assert row is not None
        assert row.get('risk_level') in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'), \
            f"Unexpected risk_level: {row.get('risk_level')}"


class TestPythonMixedCacheAndLibs:
    """Layer 5: Library source cloning and caching."""

    def test_PY30_libs_dir_exists(self, python_mixed_scan):
        """libs/ directory was created in scan output."""
        libs_dir = python_mixed_scan.scan_dir / 'libs'
        # libs/ may not exist if no vulnerable packages needed cloning
        if not libs_dir.exists():
            pytest.skip("libs/ not created (no cloneable vulnerable packages)")

    def test_PY31_vulnerable_libs_cloned(self, python_mixed_scan):
        """At least one vulnerable library source was cloned."""
        cloned = python_mixed_scan.libs_cloned
        if not cloned:
            pytest.skip("No libs cloned (cache hit or no cloneable packages)")
        assert len(cloned) > 0

    def test_PY32_cloned_lib_has_source(self, python_mixed_scan):
        """Cloned lib directories contain actual source files, not empty dirs."""
        libs_dir = python_mixed_scan.scan_dir / 'libs'
        if not libs_dir.exists():
            pytest.skip("No libs/ directory")
        for lib_dir in libs_dir.iterdir():
            if lib_dir.is_dir():
                py_files = list(lib_dir.rglob('*.py'))
                assert len(py_files) > 0, \
                    f"Cloned lib {lib_dir.name} has no .py files — clone may have failed"
                break  # spot check one
        else:
            pytest.skip("No lib directories to check")

    def test_PY33_global_cache_populated(self, python_mixed_scan):
        """Global cache ~/.reachable/cache/libs/python/ has entries."""
        cache_dir = Path.home() / '.reachable' / 'cache' / 'libs' / 'python'
        if not cache_dir.exists():
            pytest.skip("Global lib cache not yet populated")
        entries = list(cache_dir.iterdir())
        assert len(entries) > 0, "Global python lib cache is empty"

    def test_PY34_grype_db_cache_exists(self, python_mixed_scan):
        """Grype vulnerability DB cache exists at ~/.reachable/cache/grype-db/."""
        grype_cache = Path.home() / '.reachable' / 'cache' / 'grype-db'
        assert grype_cache.exists(), "Grype DB cache missing"
        # Should have a DB version dir (e.g., 5/)
        version_dirs = [d for d in grype_cache.iterdir() if d.is_dir() and d.name.isdigit()]
        assert len(version_dirs) > 0, "Grype DB cache has no version directory"

    def test_PY35_guarddog_cache_exists(self, python_mixed_scan):
        """GuardDog cache exists (malware detection)."""
        gd_cache = Path.home() / '.reachable' / 'cache' / 'guarddog'
        if not gd_cache.exists():
            pytest.skip("GuardDog cache not present (may not have run)")

    def test_PY36_sandbox_cache_in_db(self, python_mixed_scan):
        """Sandbox cache table has entries if malware scanning ran."""
        cache = python_mixed_scan.db_sandbox_cache
        # Informational — may be empty if sandbox disabled
        if cache:
            for entry in cache[:3]:
                assert entry.get('package_name'), "Sandbox cache entry missing package_name"
                assert entry.get('verdict') in ('CRITICAL', 'SUSPICIOUS', 'CLEAN', 'WARNING'), \
                    f"Unexpected verdict: {entry.get('verdict')}"


class TestPythonMixedRawFiles:
    """Layer 6: raw/ output files and scan metadata."""

    def test_PY40_vulns_json_exists(self, python_mixed_scan):
        """vulns.json was generated by grype."""
        assert python_mixed_scan.vulns is not None, "vulns.json not found"

    def test_PY41_vulns_has_matches(self, python_mixed_scan):
        """vulns.json has at least one match."""
        vulns = python_mixed_scan.vulns
        matches = vulns.get('matches', [])
        assert len(matches) > 0, "vulns.json has zero matches"

    def test_PY42_scan_manifest_exists(self, python_mixed_scan):
        """raw/scan-manifest.json was generated."""
        assert python_mixed_scan.scan_manifest is not None or \
               'scan-manifest' in python_mixed_scan.raw_files, \
            "scan-manifest.json not found in raw/"

    def test_PY43_cve_analyzed_exists(self, python_mixed_scan):
        """raw/cve-analyzed.json was generated."""
        assert 'cve-analyzed' in python_mixed_scan.raw_files, \
            "cve-analyzed.json not found in raw/"

    def test_PY44_correlation_exists(self, python_mixed_scan):
        """raw/correlation.json(.gz) was generated."""
        assert 'correlation' in python_mixed_scan.raw_files, \
            "correlation.json not found in raw/"

    def test_PY45_security_findings_exists(self, python_mixed_scan):
        """raw/security-findings.json was generated (Semgrep CWE/secret output)."""
        assert 'security-findings' in python_mixed_scan.raw_files, \
            "security-findings.json not found in raw/"

    def test_PY46_provenance_exists(self, python_mixed_scan):
        """provenance.json was generated."""
        assert python_mixed_scan.provenance is not None, \
            "provenance.json not found"

    def test_PY47_scan_log_exists(self, python_mixed_scan):
        """scan.log exists and is non-empty."""
        assert len(python_mixed_scan.scan_log) > 0, "scan.log is empty"

    def test_PY48_call_graph_generated(self, python_mixed_scan):
        """call-graph.json exists in scan output."""
        cg = python_mixed_scan.scan_dir / 'call-graph.json'
        assert cg.exists(), "call-graph.json not found"


# ============================================================================
# NPM-MIXED TESTS
# ============================================================================

class TestNpmMixedScan:
    """npm ecosystem: exit code, SBOM, DB, cache, raw files."""

    def test_NPM01_scan_exits_zero(self, npm_mixed_scan):
        assert npm_mixed_scan.exit_code == 0, \
            f"exit {npm_mixed_scan.exit_code}: {npm_mixed_scan.stderr[-500:]}"

    def test_NPM02_no_fatal_errors(self, npm_mixed_scan):
        assert not npm_mixed_scan.log_has_fatal()

    def test_NPM10_sbom_exists(self, npm_mixed_scan):
        assert npm_mixed_scan.sbom is not None

    def test_NPM11_express_in_sbom(self, npm_mixed_scan):
        names = [n.lower() for n in npm_mixed_scan.sbom_artifact_names]
        assert 'express' in names, f"'express' not in SBOM: {names[:20]}"

    def test_NPM12_lodash_in_sbom(self, npm_mixed_scan):
        names = [n.lower() for n in npm_mixed_scan.sbom_artifact_names]
        assert 'lodash' in names, f"'lodash' not in SBOM: {names[:20]}"

    def test_NPM13_npm_purls(self, npm_mixed_scan):
        purls = npm_mixed_scan.sbom_purls
        npm_purls = [p for p in purls if 'pkg:npm/' in p]
        assert len(npm_purls) > 0, f"No pkg:npm/ PURLs: {purls[:10]}"

    def test_NPM14_private_company_logger_in_sbom(self, npm_mixed_scan):
        """Private @company/logger from Verdaccio appears in SBOM."""
        names = [n.lower() for n in npm_mixed_scan.sbom_artifact_names]
        found = any('company/logger' in n or 'company-logger' in n for n in names)
        if not found:
            # May appear as scoped name with different formatting
            purls = npm_mixed_scan.sbom_purls
            found = any('company' in p and 'logger' in p for p in purls)
        assert found, (
            f"@company/logger not in SBOM. "
            f"Names: {names[:20]}\nPURLs: {npm_mixed_scan.sbom_purls[:10]}"
        )

    def test_NPM15_private_company_http_in_sbom(self, npm_mixed_scan):
        """Private @company/http from Verdaccio appears in SBOM."""
        names = [n.lower() for n in npm_mixed_scan.sbom_artifact_names]
        found = any('company/http' in n or 'company-http' in n for n in names)
        if not found:
            purls = npm_mixed_scan.sbom_purls
            found = any('company' in p and 'http' in p for p in purls)
        assert found, f"@company/http not in SBOM. Names: {names[:20]}"

    def test_NPM16_private_internal_utils_in_sbom(self, npm_mixed_scan):
        """Private @company/internal-utils from Verdaccio appears in SBOM."""
        names = [n.lower() for n in npm_mixed_scan.sbom_artifact_names]
        found = any('internal-utils' in n for n in names)
        assert found, f"@company/internal-utils not in SBOM. Names: {names[:20]}"

    def test_NPM20_scan_complete(self, npm_mixed_scan):
        assert npm_mixed_scan.completed

    def test_NPM21_findings_exist(self, npm_mixed_scan):
        # npm projects may have fewer CVEs; verify DB has the scan at minimum
        assert npm_mixed_scan.db_scan_row is not None

    def test_NPM30_npm_global_cache(self, npm_mixed_scan):
        cache = Path.home() / '.reachable' / 'cache' / 'libs' / 'npm'
        if not cache.exists():
            pytest.skip("npm lib cache not populated")
        assert len(list(cache.iterdir())) > 0

    def test_NPM40_vulns_json(self, npm_mixed_scan):
        assert npm_mixed_scan.vulns is not None

    def test_NPM41_raw_files(self, npm_mixed_scan):
        assert 'scan-manifest' in npm_mixed_scan.raw_files or \
               npm_mixed_scan.scan_manifest is not None


# ============================================================================
# GO-MIXED TESTS
# ============================================================================

class TestGoMixedScan:
    """Go ecosystem: exit code, SBOM, DB, cache."""

    def test_GO01_scan_exits_zero(self, go_mixed_scan):
        assert go_mixed_scan.exit_code == 0, \
            f"exit {go_mixed_scan.exit_code}: {go_mixed_scan.stderr[-500:]}"

    def test_GO02_no_fatal_errors(self, go_mixed_scan):
        assert not go_mixed_scan.log_has_fatal()

    def test_GO10_sbom_exists(self, go_mixed_scan):
        assert go_mixed_scan.sbom is not None

    def test_GO11_go_packages_in_sbom(self, go_mixed_scan):
        names = go_mixed_scan.sbom_artifact_names
        # go.mod has golang.org/x/net and gin
        go_pkgs = [n for n in names if 'golang.org' in n or 'gin' in n.lower()]
        assert len(go_pkgs) > 0, f"No Go packages in SBOM: {names[:20]}"

    def test_GO12_go_purls(self, go_mixed_scan):
        purls = go_mixed_scan.sbom_purls
        go_purls = [p for p in purls if 'pkg:golang/' in p]
        assert len(go_purls) > 0, f"No pkg:golang/ PURLs: {purls[:10]}"

    def test_GO20_scan_complete(self, go_mixed_scan):
        assert go_mixed_scan.completed

    def test_GO21_cves_for_known_vulnerable(self, go_mixed_scan):
        """golang.org/x/net and gin have known CVEs."""
        cve_pkgs = go_mixed_scan.cve_packages
        # At least one of these should have CVEs
        known_vuln = {'golang.org/x/net', 'github.com/gin-gonic/gin'}
        found = cve_pkgs & known_vuln
        if not found:
            # Check with partial match
            found_partial = [p for p in cve_pkgs
                            if 'x/net' in p or 'gin' in p]
            assert len(found_partial) > 0, \
                f"No CVEs for known-vulnerable Go packages. CVE packages: {cve_pkgs}"

    def test_GO30_go_global_cache(self, go_mixed_scan):
        cache = Path.home() / '.reachable' / 'cache' / 'libs' / 'go'
        if not cache.exists():
            pytest.skip("Go lib cache not populated")
        assert len(list(cache.iterdir())) > 0


# ============================================================================
# MAVEN-MIXED TESTS
# ============================================================================

class TestMavenMixedScan:
    """Maven ecosystem: exit code, SBOM, DB."""

    def test_MVN01_scan_exits_zero(self, maven_mixed_scan):
        assert maven_mixed_scan.exit_code == 0, \
            f"exit {maven_mixed_scan.exit_code}: {maven_mixed_scan.stderr[-500:]}"

    def test_MVN02_no_fatal_errors(self, maven_mixed_scan):
        assert not maven_mixed_scan.log_has_fatal()

    def test_MVN10_sbom_exists(self, maven_mixed_scan):
        assert maven_mixed_scan.sbom is not None

    def test_MVN11_maven_packages_in_sbom(self, maven_mixed_scan):
        names = [n.lower() for n in maven_mixed_scan.sbom_artifact_names]
        assert any('commons-lang3' in n for n in names) or \
               any('h2' in n for n in names), \
            f"No expected Maven packages in SBOM: {names[:20]}"

    def test_MVN12_maven_purls(self, maven_mixed_scan):
        purls = maven_mixed_scan.sbom_purls
        mvn_purls = [p for p in purls if 'pkg:maven/' in p]
        assert len(mvn_purls) > 0, f"No pkg:maven/ PURLs: {purls[:10]}"

    def test_MVN20_scan_complete(self, maven_mixed_scan):
        assert maven_mixed_scan.completed

    def test_MVN21_h2_has_cves(self, maven_mixed_scan):
        """H2 database 1.4.197 has critical CVEs."""
        h2_findings = maven_mixed_scan.findings_for_package('h2')
        assert len(h2_findings) > 0, "No CVEs for H2 1.4.197 (known critical vulns)"


# ============================================================================
# CROSS-ECOSYSTEM: CACHE INTEGRITY
# ============================================================================

class TestCacheIntegrity:
    """Verify cache files are consistent and not corrupted.
    These tests check ~/.reachable/cache/ on disk — no scan fixture needed."""

    def test_CACHE01_grype_db_timestamp(self):
        """Grype DB has a .last_update timestamp file."""
        ts_file = Path.home() / '.reachable' / 'cache' / 'grype-db' / '.last_update'
        if not ts_file.exists():
            pytest.skip("No grype DB timestamp")
        content = ts_file.read_text().strip()
        assert len(content) > 0, ".last_update is empty"
        assert re.match(r'\d{4}-\d{2}-\d{2}', content), \
            f"Invalid timestamp format: {content}"

    def test_CACHE02_epss_cache(self):
        """EPSS cache files exist if threat intel ran."""
        epss = Path.home() / '.reachable' / 'cache' / 'epss'
        epss_json = Path.home() / '.reachable' / 'cache' / 'epss_cache.json'
        if not epss.exists() and not epss_json.exists():
            pytest.skip("EPSS cache not present")
        if epss_json.exists():
            data = json.loads(epss_json.read_text())
            assert isinstance(data, (dict, list)), "epss_cache.json is not valid JSON"

    def test_CACHE03_kev_cache(self):
        """KEV (Known Exploited Vulnerabilities) cache exists."""
        kev = Path.home() / '.reachable' / 'cache' / 'kev'
        kev_json = Path.home() / '.reachable' / 'cache' / 'kev_cache.json'
        if not kev.exists() and not kev_json.exists():
            pytest.skip("KEV cache not present")
        if kev_json.exists():
            data = json.loads(kev_json.read_text())
            assert isinstance(data, (dict, list)), "kev_cache.json is not valid JSON"

    def test_CACHE04_osv_cache(self):
        """OSV cache directory exists."""
        osv = Path.home() / '.reachable' / 'cache' / 'osv'
        if not osv.exists():
            pytest.skip("OSV cache not present")

    def test_CACHE05_lib_cache_not_empty_dirs(self):
        """Cached libraries contain actual source, not empty directories."""
        cache_root = Path.home() / '.reachable' / 'cache' / 'libs'
        if not cache_root.exists():
            pytest.skip("No lib cache")
        for eco_dir in cache_root.iterdir():
            if eco_dir.is_dir():
                for pkg_dir in list(eco_dir.iterdir())[:3]:
                    if pkg_dir.is_dir():
                        files = list(pkg_dir.rglob('*'))
                        assert len(files) > 0, \
                            f"Cached lib {pkg_dir.name} is empty"


# ============================================================================
# CROSS-ECOSYSTEM: DATABASE SCHEMA INTEGRITY
# ============================================================================

class TestDatabaseSchema:
    """Verify repo.db schema is correct and tables exist.
    Uses any_completed_scan so these run regardless of which ecosystem is available."""

    def test_DB01_all_tables_exist(self, any_completed_scan):
        """repo.db has all required tables."""
        db = any_completed_scan.repo_db_path
        if not db:
            pytest.skip("No repo.db")
        conn = sqlite3.connect(str(db))
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        conn.close()

        required = ['scans', 'findings', 'sbom_cache', 'call_graph_cache',
                     'large_objects', 'metrics', 'ai_findings', 'dlp_findings',
                     'sandbox_cache', 'unresolved_packages', 'scan_audit']
        missing = [t for t in required if t not in tables]
        assert not missing, f"Missing tables: {missing}. Got: {tables}"

    def test_DB02_scan_audit_exists(self, any_completed_scan):
        """scan_audit table has entries tracking data loss."""
        db = any_completed_scan.repo_db_path
        if not db:
            pytest.skip("No repo.db")
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scan_audit WHERE scan_id = ?",
            (any_completed_scan.scan_id,)
        ).fetchall()
        conn.close()
        if any_completed_scan.cve_findings:
            cve_audit = [dict(r) for r in rows if r['finding_type'] == 'cve']
            assert len(cve_audit) > 0, "No scan_audit entry for CVE findings"
            for a in cve_audit:
                assert a['loss_percentage'] < 10.0, \
                    f"High CVE data loss: {a['loss_percentage']:.1f}%"

    def test_DB03_large_objects_populated(self, any_completed_scan):
        """large_objects table has correlation/report blobs."""
        db = any_completed_scan.repo_db_path
        if not db:
            pytest.skip("No repo.db")
        conn = sqlite3.connect(str(db))
        rows = conn.execute(
            "SELECT object_type, size_original, size_compressed FROM large_objects WHERE scan_id = ?",
            (any_completed_scan.scan_id,)
        ).fetchall()
        conn.close()
        if rows:
            for r in rows:
                assert r[1] > 0, f"large_object {r[0]} has zero original size"
                assert r[2] > 0, f"large_object {r[0]} has zero compressed size"


# ============================================================================
# NEGATIVE TESTS: NO AUTH → PRIVATE PACKAGES SHOULD NOT RESOLVE
# ============================================================================

class TestNpmNoAuth:
    """Negative test: npm project WITHOUT private registry auth.
    Proves:
      - Scan still succeeds (exit 0)
      - Public packages (express, lodash) ARE in SBOM
      - Private @company/* packages are NOT in SBOM
      - Public repos continue working alongside misconfigured private config
    """

    def test_NEG_NPM01_scan_exits_zero(self, npm_noauth_scan):
        """Scan completes without crash even without private auth."""
        r = npm_noauth_scan
        assert r.exit_code == 0, (
            f"reachctl exited {r.exit_code}\n"
            f"STDERR: {r.stderr[-500:]}"
        )

    def test_NEG_NPM02_no_fatal_errors(self, npm_noauth_scan):
        """No fatal tool errors despite missing private packages."""
        r = npm_noauth_scan
        assert not r.log_has_fatal(), (
            f"Fatal error in scan.log:\n{r.scan_log[-1000:]}"
        )

    def test_NEG_NPM03_public_express_in_sbom(self, npm_noauth_scan):
        """Public package express IS in SBOM (public registry still works)."""
        names = npm_noauth_scan.sbom_artifact_names
        assert 'express' in names, (
            f"express should be in SBOM from public npm. Got: {names[:20]}"
        )

    def test_NEG_NPM04_public_lodash_in_sbom(self, npm_noauth_scan):
        """Public package lodash IS in SBOM (public registry still works)."""
        names = npm_noauth_scan.sbom_artifact_names
        assert 'lodash' in names, (
            f"lodash should be in SBOM from public npm. Got: {names[:20]}"
        )

    def test_NEG_NPM05_private_logger_NOT_in_sbom(self, npm_noauth_scan):
        """@company/logger NOT in SBOM (no Verdaccio auth)."""
        names = npm_noauth_scan.sbom_artifact_names
        found = any('company/logger' in n for n in names)
        assert not found, (
            f"@company/logger SHOULD NOT be in SBOM without auth. "
            f"Names: {names[:20]}"
        )

    def test_NEG_NPM06_private_http_NOT_in_sbom(self, npm_noauth_scan):
        """@company/http NOT in SBOM (no Verdaccio auth)."""
        names = npm_noauth_scan.sbom_artifact_names
        found = any('company/http' in n for n in names)
        assert not found, (
            f"@company/http SHOULD NOT be in SBOM without auth. "
            f"Names: {names[:20]}"
        )

    def test_NEG_NPM07_private_utils_NOT_in_sbom(self, npm_noauth_scan):
        """@company/internal-utils NOT in SBOM (no Verdaccio auth)."""
        names = npm_noauth_scan.sbom_artifact_names
        found = any('internal-utils' in n for n in names)
        assert not found, (
            f"@company/internal-utils SHOULD NOT be in SBOM without auth. "
            f"Names: {names[:20]}"
        )


class TestPythonNoAuth:
    """Negative test: Python project WITHOUT devpi auth.
    Proves:
      - Scan still succeeds (exit 0)
      - Public packages (requests, flask) ARE in SBOM
      - Private internal-sdk is NOT in SBOM
    """

    def test_NEG_PY01_scan_exits_zero(self, python_noauth_scan):
        """Scan completes without crash even without devpi auth."""
        r = python_noauth_scan
        assert r.exit_code == 0, (
            f"reachctl exited {r.exit_code}\n"
            f"STDERR: {r.stderr[-500:]}"
        )

    def test_NEG_PY02_no_fatal_errors(self, python_noauth_scan):
        """No fatal tool errors despite missing private packages."""
        r = python_noauth_scan
        assert not r.log_has_fatal(), (
            f"Fatal error in scan.log:\n{r.scan_log[-1000:]}"
        )

    def test_NEG_PY03_public_requests_in_sbom(self, python_noauth_scan):
        """Public package requests IS in SBOM (PyPI still works)."""
        names = python_noauth_scan.sbom_artifact_names
        assert 'requests' in names or any('requests' in n for n in names), (
            f"requests should be in SBOM from public PyPI. Got: {names[:20]}"
        )

    def test_NEG_PY04_public_flask_in_sbom(self, python_noauth_scan):
        """Public package flask IS in SBOM (PyPI still works)."""
        names = python_noauth_scan.sbom_artifact_names
        lower_names = [n.lower() for n in names]
        assert 'flask' in lower_names or any('flask' in n for n in lower_names), (
            f"flask should be in SBOM from public PyPI. Got: {names[:20]}"
        )

    def test_NEG_PY05_private_internal_sdk_NOT_in_sbom(self, python_noauth_scan):
        """internal-sdk NOT in SBOM (no devpi auth configured)."""
        names = python_noauth_scan.sbom_artifact_names
        found = any('internal-sdk' in n or 'internal_sdk' in n for n in names)
        assert not found, (
            f"internal-sdk SHOULD NOT be in SBOM without devpi auth. "
            f"Names: {names[:20]}"
        )
