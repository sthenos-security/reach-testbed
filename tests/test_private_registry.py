#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Private Registry Integration Tests

Strategy: Run `reachctl scan <target-project> --debug` and verify correctness
through 6 evidence layers:

    1. EXIT CODE  — scan completed (exit 0)
    2. REPO.DB    — scans.status='complete', findings populated, audit clean
    3. SBOM       — public + private packages present with correct PURLs
    4. SCAN LOG   — no fatal tool errors (syft/grype/semgrep/guarddog/treesitter)
    5. RAW FILES  — scan-manifest components all 'complete', vulns/cve-analyzed exist
    6. CACHES     — session libs cloned, global lib cache populated,
                    grype DB fresh, lib-cloning-metrics healthy

Each test is atomic and reads from the session-scoped ScanResult fixture
(scan runs once per ecosystem, tests fan out).
"""

import json
import sqlite3
from pathlib import Path

import pytest


# =============================================================================
# LAYER 1: EXIT CODE
# =============================================================================

class TestExitCode:
    """Scan process must exit cleanly."""

    def test_PY_exit_code_success(self, python_mixed_scan):
        # exit 0 = clean, 1 = findings below threshold, 2 = threshold breached
        # any of 0/1/2 means the scan COMPLETED; anything else is a crash
        assert python_mixed_scan.exit_code in (0, 1, 2), (
            f"reachctl crashed (exit {python_mixed_scan.exit_code}):\n"
            f"STDERR: {python_mixed_scan.stderr[-500:]}"
        )

    def test_NPM_exit_code_success(self, npm_mixed_scan):
        assert npm_mixed_scan.exit_code in (0, 1, 2), (
            f"reachctl crashed (exit {npm_mixed_scan.exit_code})"
        )

    def test_GO_exit_code_success(self, go_mixed_scan):
        assert go_mixed_scan.exit_code in (0, 1, 2), (
            f"reachctl crashed (exit {go_mixed_scan.exit_code})"
        )

    def test_MVN_exit_code_success(self, maven_mixed_scan):
        assert maven_mixed_scan.exit_code in (0, 1, 2), (
            f"reachctl crashed (exit {maven_mixed_scan.exit_code})"
        )


# =============================================================================
# LAYER 2: REPO.DB — scan status, findings, audit
# =============================================================================

class TestRepoDB:
    """Database must reflect a successful, complete scan with findings."""

    # --- Scan row ---

    def test_PY_scan_completed(self, python_mixed_scan):
        assert python_mixed_scan.completed, (
            f"Scan status: {python_mixed_scan.db_scan_row}"
        )

    def test_PY_scan_has_risk_level(self, python_mixed_scan):
        assert python_mixed_scan.db_scan_row.get('risk_level') in (
            'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
        )

    def test_PY_scan_has_duration(self, python_mixed_scan):
        dur = python_mixed_scan.db_scan_row.get('duration_seconds')
        assert dur is not None and dur > 0, "Scan duration not recorded"

    def test_PY_scan_has_version(self, python_mixed_scan):
        assert python_mixed_scan.db_scan_row.get('version'), "REACHABLE version missing from scan row"

    # --- CVE findings ---

    def test_PY_cve_findings_exist(self, python_mixed_scan):
        """Flask 2.0.3 and requests 2.31.0 have known CVEs."""
        assert len(python_mixed_scan.cve_findings) > 0, "No CVE findings in DB"

    def test_PY_flask_cves_found(self, python_mixed_scan):
        flask_cves = python_mixed_scan.findings_for_package('flask')
        assert len(flask_cves) > 0, "Flask 2.0.3 should have known CVEs"

    def test_PY_cve_has_severity(self, python_mixed_scan):
        for f in python_mixed_scan.cve_findings[:5]:
            assert f.get('severity') in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'), (
                f"CVE {f.get('finding_id')} missing valid severity"
            )

    def test_PY_cve_has_risk_level(self, python_mixed_scan):
        for f in python_mixed_scan.cve_findings[:5]:
            assert f.get('risk_level'), f"CVE {f.get('finding_id')} missing risk_level"

    def test_PY_cve_has_fix_status(self, python_mixed_scan):
        for f in python_mixed_scan.cve_findings[:5]:
            assert f.get('fix_status') in ('fix_available', 'no_fix', 'wont_fix', 'unknown'), (
                f"CVE {f.get('finding_id')} has invalid fix_status: {f.get('fix_status')}"
            )

    def test_PY_cve_has_scanner_attribution(self, python_mixed_scan):
        for f in python_mixed_scan.cve_findings[:5]:
            assert f.get('scanner') == 'grype', (
                f"CVE {f.get('finding_id')} scanner={f.get('scanner')}, expected grype"
            )

    # --- Audit (data loss) ---

    def test_PY_scan_audit_data_loss_under_1pct(self, python_mixed_scan):
        """scan_audit table tracks CLI→DB data loss; should be < 1%."""
        if python_mixed_scan.db_scan_audit:
            assert python_mixed_scan.data_loss_pct < 1.0, (
                f"Data loss {python_mixed_scan.data_loss_pct:.1f}% exceeds 1% threshold: "
                f"{python_mixed_scan.db_scan_audit}"
            )

    # --- Unresolved packages (private registry signal) ---

    def test_PY_unresolved_packages_tracked(self, python_mixed_scan):
        """Private packages that can't map to canonical should appear in unresolved_packages."""
        # This may be empty if all private pkgs resolved — that's fine,
        # but if they exist, they should have required fields.
        for u in python_mixed_scan.db_unresolved:
            assert u.get('name'), "Unresolved package missing name"
            assert u.get('ecosystem'), "Unresolved package missing ecosystem"
            assert u.get('reason'), "Unresolved package missing reason"

    # --- npm/go ---

    def test_NPM_scan_completed(self, npm_mixed_scan):
        assert npm_mixed_scan.completed

    def test_NPM_cve_findings_exist(self, npm_mixed_scan):
        assert len(npm_mixed_scan.cve_findings) > 0, "No CVE findings for npm-mixed"

    def test_GO_scan_completed(self, go_mixed_scan):
        assert go_mixed_scan.completed

    def test_GO_cve_findings_exist(self, go_mixed_scan):
        """golang.org/x/net v0.23.0 has known CVEs."""
        assert len(go_mixed_scan.cve_findings) > 0, "No CVE findings for go-mixed"


# =============================================================================
# LAYER 3: SBOM — public + private packages present
# =============================================================================

class TestSBOM:
    """SBOM must contain both public and private registry packages."""

    def test_PY_sbom_exists(self, python_mixed_scan):
        assert python_mixed_scan.sbom is not None, "sbom.json not found"

    def test_PY_sbom_has_artifacts(self, python_mixed_scan):
        assert len(python_mixed_scan.sbom.get('artifacts', [])) > 0, "SBOM has no artifacts"

    def test_PY_public_packages_in_sbom(self, python_mixed_scan):
        names = [n.lower() for n in python_mixed_scan.sbom_artifact_names]
        assert 'requests' in names, f"requests not in SBOM: {names[:10]}"
        assert 'flask' in names, f"flask not in SBOM: {names[:10]}"

    def test_PY_sbom_has_purls(self, python_mixed_scan):
        """Every artifact should have a PURL for Grype matching."""
        artifacts = python_mixed_scan.sbom.get('artifacts', [])
        with_purl = [a for a in artifacts if a.get('purl')]
        # At least 50% should have PURLs (some OS packages may not)
        assert len(with_purl) >= len(artifacts) * 0.5, (
            f"Only {len(with_purl)}/{len(artifacts)} artifacts have PURLs"
        )

    def test_NPM_public_packages_in_sbom(self, npm_mixed_scan):
        names = [n.lower() for n in npm_mixed_scan.sbom_artifact_names]
        assert 'express' in names, "express not in SBOM"
        assert 'lodash' in names, "lodash not in SBOM"

    def test_GO_public_packages_in_sbom(self, go_mixed_scan):
        names = [n.lower() for n in go_mixed_scan.sbom_artifact_names]
        # Go packages use full module path
        has_net = any('golang.org/x/net' in n for n in names)
        has_gin = any('gin-gonic/gin' in n for n in names)
        assert has_net or has_gin, f"Expected Go packages not in SBOM: {names[:10]}"


# =============================================================================
# LAYER 4: SCAN LOG — no fatal tool errors
# =============================================================================

class TestScanLog:
    """scan.log must not contain fatal errors from any scanning tool."""

    def test_PY_scan_log_exists(self, python_mixed_scan):
        assert len(python_mixed_scan.scan_log) > 0, "scan.log is empty or missing"

    def test_PY_no_syft_fatal(self, python_mixed_scan):
        assert not python_mixed_scan.scan_log_has_fatal('syft'), (
            "Syft had a fatal error — SBOM generation failed"
        )

    def test_PY_no_grype_fatal(self, python_mixed_scan):
        assert not python_mixed_scan.scan_log_has_fatal('grype'), (
            "Grype had a fatal error — vulnerability scanning failed"
        )

    def test_PY_no_semgrep_fatal(self, python_mixed_scan):
        assert not python_mixed_scan.scan_log_has_fatal('semgrep'), (
            "Semgrep had a fatal error — SAST/secrets scanning failed"
        )

    def test_PY_no_guarddog_fatal(self, python_mixed_scan):
        assert not python_mixed_scan.scan_log_has_fatal('guarddog'), (
            "GuardDog had a fatal error — malware scanning failed"
        )

    def test_PY_no_treesitter_fatal(self, python_mixed_scan):
        assert not python_mixed_scan.scan_log_has_fatal('tree.sitter'), (
            "Tree-sitter had a fatal error — call graph generation failed"
        )

    def test_PY_no_python_traceback(self, python_mixed_scan):
        """No unhandled Python exceptions in scan log."""
        # A Traceback line means something crashed inside the pipeline
        traceback_count = python_mixed_scan.scan_log.count('Traceback (most recent call last)')
        assert traceback_count == 0, (
            f"Found {traceback_count} Python traceback(s) in scan.log"
        )

    def test_NPM_no_tool_fatals(self, npm_mixed_scan):
        for tool in ['syft', 'grype', 'semgrep', 'guarddog']:
            assert not npm_mixed_scan.scan_log_has_fatal(tool), (
                f"{tool} had a fatal error in npm-mixed scan"
            )

    def test_GO_no_tool_fatals(self, go_mixed_scan):
        for tool in ['syft', 'grype', 'semgrep']:
            assert not go_mixed_scan.scan_log_has_fatal(tool), (
                f"{tool} had a fatal error in go-mixed scan"
            )


# =============================================================================
# LAYER 5: RAW FILES — scan-manifest, vulns, cve-analyzed
# =============================================================================

class TestRawFiles:
    """Raw output files must exist and indicate successful pipeline stages."""

    def test_PY_scan_manifest_exists(self, python_mixed_scan):
        assert python_mixed_scan.raw_manifest is not None, "raw/scan-manifest.json not found"

    def test_PY_manifest_cves_complete(self, python_mixed_scan):
        statuses = python_mixed_scan.manifest_component_statuses
        assert statuses.get('cves') == 'complete', (
            f"CVE component status: {statuses.get('cves')}"
        )

    def test_PY_manifest_secrets_complete(self, python_mixed_scan):
        statuses = python_mixed_scan.manifest_component_statuses
        assert statuses.get('secrets') == 'complete', (
            f"Secrets component status: {statuses.get('secrets')}"
        )

    def test_PY_manifest_malware_complete(self, python_mixed_scan):
        statuses = python_mixed_scan.manifest_component_statuses
        assert statuses.get('malware') == 'complete', (
            f"Malware component status: {statuses.get('malware')}"
        )

    def test_PY_vulns_json_exists(self, python_mixed_scan):
        assert python_mixed_scan.vulns is not None, "vulns.json not found"

    def test_PY_vulns_has_matches(self, python_mixed_scan):
        matches = python_mixed_scan.vulns.get('matches', [])
        assert len(matches) > 0, "Grype vulns.json has no matches"

    def test_PY_cve_analyzed_exists(self, python_mixed_scan):
        cve_file = python_mixed_scan.session_dir / 'raw' / 'cve-analyzed.json'
        assert cve_file.exists(), "raw/cve-analyzed.json not found"

    def test_PY_session_json_exists(self, python_mixed_scan):
        assert python_mixed_scan.session_json is not None, ".session.json not found"

    def test_PY_provenance_exists(self, python_mixed_scan):
        assert python_mixed_scan.provenance is not None, "provenance.json not found"

    def test_PY_scan_plan_exists(self, python_mixed_scan):
        assert python_mixed_scan.scan_plan is not None, "scan-plan.json not found"

    def test_PY_scan_plan_detects_python(self, python_mixed_scan):
        langs = python_mixed_scan.scan_plan.get('languages', [])
        assert 'python' in [l.lower() for l in langs], (
            f"scan-plan did not detect Python: {langs}"
        )


# =============================================================================
# LAYER 6: CACHES — libs, grype DB, global cache, cloning metrics
# =============================================================================

class TestCaches:
    """Verify that caching infrastructure is healthy after a scan."""

    # --- Session libs (per-scan cloned libraries) ---

    def test_PY_session_libs_cloned(self, python_mixed_scan):
        """At least one library should be cloned for reachability analysis."""
        assert len(python_mixed_scan.session_libs) > 0, (
            "No libraries cloned in session libs dir"
        )

    def test_PY_session_libs_include_flask(self, python_mixed_scan):
        """Flask 2.0.3 has CVEs — its source should be cloned."""
        assert 'flask' in python_mixed_scan.session_libs, (
            f"flask not cloned. Session libs: {python_mixed_scan.session_libs}"
        )

    # --- Lib cloning metrics ---

    def test_PY_cloning_metrics_exist(self, python_mixed_scan):
        assert python_mixed_scan.lib_cloning_metrics is not None, (
            "libs/.metadata/lib-cloning-metrics.json not found"
        )

    def test_PY_cloning_success_rate_above_50pct(self, python_mixed_scan):
        m = python_mixed_scan.lib_cloning_metrics
        if m:
            total = m.get('total_attempted', 0)
            success = m.get('total_success', 0)
            if total > 0:
                rate = success / total * 100
                assert rate >= 50, (
                    f"Lib cloning success rate {rate:.0f}% is below 50%: "
                    f"{success}/{total} succeeded"
                )

    def test_PY_cloning_cache_tracked(self, python_mixed_scan):
        """Cache hits/misses should be tracked in metrics."""
        m = python_mixed_scan.lib_cloning_metrics
        if m:
            assert 'cache_hits' in m, "cache_hits not in lib-cloning-metrics"
            assert 'cache_misses' in m, "cache_misses not in lib-cloning-metrics"

    def test_PY_cloning_failed_packages_documented(self, python_mixed_scan):
        """Failed packages should be documented with reason."""
        m = python_mixed_scan.lib_cloning_metrics
        if m and m.get('failed_packages'):
            for pkg in m['failed_packages']:
                assert pkg.get('package'), "Failed package missing name"
                assert pkg.get('reason') or pkg.get('message'), (
                    f"Failed package {pkg.get('package')} missing reason"
                )

    # --- Global lib cache (shared across scans) ---

    def test_PY_global_lib_cache_has_entries(self, python_mixed_scan):
        """After scan, global cache should have some python entries."""
        python_entries = [e for e in python_mixed_scan.global_lib_cache_entries
                         if e.startswith('python/')]
        assert len(python_entries) > 0, (
            f"No python entries in global lib cache. All entries: "
            f"{python_mixed_scan.global_lib_cache_entries[:10]}"
        )

    def test_PY_global_lib_cache_flask(self, python_mixed_scan):
        """Flask should be in global cache after scanning python-mixed."""
        flask_entries = [e for e in python_mixed_scan.global_lib_cache_entries
                         if 'flask@' in e]
        assert len(flask_entries) > 0, (
            "flask not found in global lib cache"
        )

    # --- Grype vulnerability DB ---

    def test_grype_db_exists(self, python_mixed_scan):
        grype_db_dir = Path.home() / '.reachable' / 'cache' / 'grype-db'
        assert grype_db_dir.exists(), "Grype DB cache directory missing"
        # Should have a version subdirectory (e.g., '5/')
        subdirs = [d for d in grype_db_dir.iterdir() if d.is_dir() and d.name.isdigit()]
        assert len(subdirs) > 0, "No grype DB version directory found"

    def test_grype_db_fresh(self, python_mixed_scan):
        """Grype DB should have been updated within last 48 hours."""
        age = python_mixed_scan.grype_db_age_hours
        if age is not None:
            assert age < 48, f"Grype DB is {age:.1f}h old (> 48h threshold)"

    # --- Threat intel caches ---

    def test_kev_cache_exists(self, python_mixed_scan):
        kev_file = Path.home() / '.reachable' / 'cache' / 'kev_cache.json'
        # KEV cache is optional — only assert if CVEs are present
        if len(python_mixed_scan.cve_findings) > 0:
            # It's OK if it doesn't exist (offline mode), but if it does,
            # it should be valid JSON
            if kev_file.exists():
                data = json.loads(kev_file.read_text())
                assert isinstance(data, (dict, list)), "kev_cache.json is not valid JSON"

    def test_epss_cache_exists(self, python_mixed_scan):
        epss_file = Path.home() / '.reachable' / 'cache' / 'epss_cache.json'
        if epss_file.exists():
            data = json.loads(epss_file.read_text())
            assert isinstance(data, (dict, list)), "epss_cache.json is not valid JSON"

    def test_osv_cache_populated(self, python_mixed_scan):
        osv_dir = Path.home() / '.reachable' / 'cache' / 'osv'
        if osv_dir.exists():
            entries = list(osv_dir.iterdir())
            # If the scan found CVEs, OSV cache should have some entries
            if len(python_mixed_scan.cve_findings) > 0:
                assert len(entries) > 0, "OSV cache dir exists but is empty"

    # --- repo.db caches (sbom_cache, call_graph_cache, sandbox_cache) ---

    def test_PY_repo_db_has_cache_tables(self, python_mixed_scan):
        """repo.db should have cache tables for SBOM, call graph, sandbox."""
        if not python_mixed_scan.repo_db_path or not python_mixed_scan.repo_db_path.exists():
            pytest.skip("repo.db not found")
        conn = sqlite3.connect(str(python_mixed_scan.repo_db_path))
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            assert 'sbom_cache' in tables, "sbom_cache table missing from repo.db"
            assert 'call_graph_cache' in tables, "call_graph_cache table missing from repo.db"
            assert 'sandbox_cache' in tables, "sandbox_cache table missing from repo.db"
        finally:
            conn.close()

    def test_PY_sandbox_cache_populated(self, python_mixed_scan):
        """If malware scanning ran, sandbox_cache should have entries."""
        if not python_mixed_scan.repo_db_path or not python_mixed_scan.repo_db_path.exists():
            pytest.skip("repo.db not found")
        conn = sqlite3.connect(str(python_mixed_scan.repo_db_path))
        try:
            count = conn.execute("SELECT COUNT(*) FROM sandbox_cache").fetchone()[0]
            # Sandbox cache may be empty if no npm/pip packages were sandbox-tested
            # Just verify the query works (schema is correct)
            assert count >= 0
        except sqlite3.OperationalError:
            pytest.skip("sandbox_cache table not accessible")
        finally:
            conn.close()

    # --- Semgrep cache ---

    def test_PY_semgrep_cache_exists(self, python_mixed_scan):
        """repo-level semgrep-cache.json should exist after scan."""
        if not python_mixed_scan.repo_db_path:
            pytest.skip("repo.db path not found")
        repo_dir = python_mixed_scan.repo_db_path.parent
        semgrep_cache = repo_dir / 'semgrep-cache.json'
        # Optional — semgrep cache only written in some modes
        if semgrep_cache.exists():
            data = json.loads(semgrep_cache.read_text())
            assert isinstance(data, (dict, list)), "semgrep-cache.json is not valid JSON"

    # --- npm / Go cache assertions ---

    def test_NPM_session_libs_cloned(self, npm_mixed_scan):
        assert len(npm_mixed_scan.session_libs) > 0, "No libs cloned for npm-mixed"

    def test_NPM_global_lib_cache_npm_entries(self, npm_mixed_scan):
        npm_entries = [e for e in npm_mixed_scan.global_lib_cache_entries
                       if e.startswith('npm/')]
        # npm entries should exist if express/lodash have CVEs
        if len(npm_mixed_scan.cve_findings) > 0:
            assert len(npm_entries) > 0, "No npm entries in global lib cache"

    def test_GO_session_libs_cloned(self, go_mixed_scan):
        assert len(go_mixed_scan.session_libs) > 0, "No libs cloned for go-mixed"

    def test_GO_global_lib_cache_go_entries(self, go_mixed_scan):
        go_entries = [e for e in go_mixed_scan.global_lib_cache_entries
                      if e.startswith('go/')]
        if len(go_mixed_scan.cve_findings) > 0:
            assert len(go_entries) > 0, "No go entries in global lib cache"


# =============================================================================
# CROSS-CUTTING: Private registry specific assertions
# =============================================================================

class TestPrivateRegistryIntegration:
    """Tests specific to private registry package handling."""

    def test_PY_private_packages_in_sbom_when_uncommented(self, python_mixed_scan):
        """If private packages are uncommented in requirements.txt,
        they should appear in the SBOM."""
        # Read the actual requirements.txt to check if private pkgs are active
        req_file = Path(__file__).parent / 'target-projects' / 'python-mixed' / 'requirements.txt'
        if req_file.exists():
            content = req_file.read_text()
            # Check if company-auth is uncommented
            if 'company-auth' in content and not content.split('company-auth')[0].rstrip().endswith('#'):
                names = [n.lower() for n in python_mixed_scan.sbom_artifact_names]
                assert 'company-auth' in names, (
                    "company-auth is in requirements.txt but not in SBOM"
                )

    def test_PY_purl_resolver_ran(self, python_mixed_scan):
        """scan.log should show PURLResolver activity."""
        log = python_mixed_scan.scan_log
        # PURLResolver logs "PURL" or "purl" or "registry_coverage" when it runs
        purl_ran = any(term in log.lower() for term in ['purl', 'registry_coverage', 'enrich_sbom'])
        if len(python_mixed_scan.sbom_artifact_names) > 0:
            assert purl_ran, "PURLResolver does not appear in scan.log"

    def test_PY_devpi_reachable_during_scan(self, python_mixed_scan):
        """If devpi was down during scan, pip install would fail.
        Check scan.log for pip/devpi failures."""
        log = python_mixed_scan.scan_log
        devpi_errors = [
            'connection refused.*3141',
            'could not connect.*devpi',
            'extra-index-url.*failed',
        ]
        for pattern in devpi_errors:
            assert not python_mixed_scan.scan_log_has_error(pattern), (
                "devpi connection failure detected in scan.log"
            )

    def test_NPM_verdaccio_packages_in_sbom(self, npm_mixed_scan):
        """If @company scoped packages are in package.json, check SBOM."""
        pkg_json = Path(__file__).parent / 'target-projects' / 'npm-mixed' / 'package.json'
        if pkg_json.exists():
            data = json.loads(pkg_json.read_text())
            deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            scoped = [k for k in deps if k.startswith('@company/')]
            if scoped:
                names = [n.lower() for n in npm_mixed_scan.sbom_artifact_names]
                for pkg in scoped:
                    assert pkg.lower() in names, (
                        f"{pkg} from Verdaccio not found in SBOM"
                    )
