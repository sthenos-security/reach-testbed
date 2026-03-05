#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Integration tests for PURLResolver + lib_manager with real Docker registries.

Tests private, public, and mixed-registry packages across Python, npm, Go,
and Maven — all in the same scan pipeline.

Requires:
    cd private-registry && docker compose up -d --wait && ./setup.sh

Run:
    pytest tests/test_purl_resolver_integration.py -v
    pytest tests/test_purl_resolver_integration.py -v -k "PY06 or JS05 or GO05 or MV05"
    pytest tests/test_purl_resolver_integration.py -v -k "ML01"
"""


import pytest

# Import shared helpers
from test_helpers import pkg, cves_for, grype_results_for  # noqa: E402

# ---------------------------------------------------------------------------
# Skip decorator for Grype-dependent tests
# ---------------------------------------------------------------------------
import shutil
requires_grype = pytest.mark.skipif(
    not shutil.which('grype'), reason='Grype not installed'
)


# ===================================================================
# Python — Mixed Public + Private Registry
# ===================================================================

class TestPythonMixedRegistry:
    """PY-01 through PY-06: devpi mirror + genuine private + public PyPI."""

    def test_PY01_public_package_unchanged(self, python_mixed_sbom_resolved):
        """Public packages must pass through resolver unchanged."""
        a = pkg(python_mixed_sbom_resolved, 'requests', '2.31.0')
        assert a['purl'] == 'pkg:pypi/requests@2.31.0'
        reg = a.get('_reachable_registry', {})
        assert reg.get('resolution', 'canonical') == 'canonical'

    def test_PY02_flask_public_unchanged(self, python_mixed_sbom_resolved):
        a = pkg(python_mixed_sbom_resolved, 'flask')
        assert 'flask' in a['purl'].lower()

    def test_PY05_coverage_metadata_present(self, python_mixed_sbom_resolved):
        """Enriched SBOM must include coverage stats."""
        cov = python_mixed_sbom_resolved.get('_reachable_registry_coverage')
        if cov is None:
            pytest.skip('Resolver returned original (no rewrites needed)')
        assert cov['total_packages'] > 0

    @requires_grype
    def test_PY06_grype_finds_public_cves(self, python_mixed_sbom_resolved):
        """Flask 2.0.3 has known CVEs — Grype must find them."""
        grype = grype_results_for(python_mixed_sbom_resolved)
        flask_cves = cves_for(grype, 'flask')
        assert len(flask_cves) > 0, 'Flask 2.0.3 should have known CVEs'

    @requires_grype
    def test_PY06_lib_manager_gaps_explicit(self, python_mixed_result):
        """Any unfetchable package must produce an explicit gap."""
        gaps = python_mixed_result.get('call_graph_gaps', [])
        for gap in gaps:
            assert 'name' in gap
            assert 'reason' in gap
            assert gap['reason'] in (
                'source_fetch_failed', 'no_source_repository',
                'gonosumcheck_excluded',
            )


# ===================================================================
# npm — Mixed Public + Verdaccio Scoped Packages
# ===================================================================

class TestNpmMixedRegistry:
    """JS-01 through JS-05: Verdaccio @company/* + public npmjs."""

    def test_JS01_public_express_in_sbom(self, npm_mixed_sbom_resolved):
        a = pkg(npm_mixed_sbom_resolved, 'express')
        assert 'express' in a['purl']

    def test_JS01_public_lodash_in_sbom(self, npm_mixed_sbom_resolved):
        a = pkg(npm_mixed_sbom_resolved, 'lodash')
        assert 'lodash' in a['purl']

    @requires_grype
    def test_JS05_grype_finds_public_npm_cves(self, npm_mixed_sbom_resolved):
        grype = grype_results_for(npm_mixed_sbom_resolved)
        express_cves = cves_for(grype, 'express')
        lodash_cves = cves_for(grype, 'lodash')
        assert len(express_cves) > 0 or len(lodash_cves) > 0, \
            'At least one public npm package should have CVEs'

    @requires_grype
    def test_JS05_lib_manager_gaps_explicit(self, npm_mixed_result):
        gaps = npm_mixed_result.get('call_graph_gaps', [])
        for gap in gaps:
            assert 'name' in gap and 'reason' in gap


# ===================================================================
# Go — Mixed Public + Athens Mirror
# ===================================================================

class TestGoMixedRegistry:
    """GO-01 through GO-05: Athens-proxied public Go modules."""

    def test_GO01_public_xnet_in_sbom(self, go_mixed_sbom_resolved):
        found = any(
            'golang.org/x/net' in a.get('name', '') or 'x/net' in a.get('purl', '')
            for a in go_mixed_sbom_resolved.get('artifacts', [])
        )
        assert found, 'golang.org/x/net not found in Go SBOM'

    def test_GO01_gin_in_sbom(self, go_mixed_sbom_resolved):
        found = any(
            'gin' in a.get('name', '').lower()
            for a in go_mixed_sbom_resolved.get('artifacts', [])
        )
        assert found, 'gin not found in Go SBOM'

    @requires_grype
    def test_GO05_grype_runs_on_go_sbom(self, go_mixed_sbom_resolved):
        grype = grype_results_for(go_mixed_sbom_resolved)
        assert isinstance(grype.get('matches', []), list)


# ===================================================================
# Maven — Mixed Public + Reposilite Private
# ===================================================================

class TestMavenMixedRegistry:
    """MV-01 through MV-05: Reposilite private + Maven Central."""

    def test_MV01_h2_in_sbom(self, maven_mixed_sbom_resolved):
        found = any(
            'h2' in a.get('name', '').lower()
            for a in maven_mixed_sbom_resolved.get('artifacts', [])
        )
        assert found, 'h2 not found in Maven SBOM'

    def test_MV01_commons_lang3_in_sbom(self, maven_mixed_sbom_resolved):
        found = any(
            'commons-lang3' in a.get('name', '')
            for a in maven_mixed_sbom_resolved.get('artifacts', [])
        )
        assert found, 'commons-lang3 not found in Maven SBOM'

    @requires_grype
    def test_MV05_grype_finds_maven_cves(self, maven_mixed_sbom_resolved):
        grype = grype_results_for(maven_mixed_sbom_resolved)
        h2_cves = cves_for(grype, 'h2')
        # h2 1.4.197 has known CVEs (e.g. CVE-2018-10054, CVE-2021-23463)
        assert len(h2_cves) > 0, 'h2 1.4.197 should have known CVEs'

    @requires_grype
    def test_MV05_lib_manager_gaps_explicit(self, maven_mixed_result):
        gaps = maven_mixed_result.get('call_graph_gaps', [])
        for gap in gaps:
            assert 'name' in gap and 'reason' in gap


# ===================================================================
# Polyglot — All Languages in One Scan
# ===================================================================

class TestPolyglotMixedRegistry:
    """ML-01: Python + npm + Go + Maven in a single scan."""

    def test_ML01_all_ecosystems_present_in_sbom(self, polyglot_sbom_resolved):
        """The polyglot SBOM must contain artifacts from all four ecosystems."""
        purls = [a.get('purl', '') for a in polyglot_sbom_resolved.get('artifacts', [])]
        purl_str = ' '.join(purls)

        assert 'pkg:pypi/' in purl_str, 'No Python artifacts in polyglot SBOM'
        assert 'pkg:npm/' in purl_str, 'No npm artifacts in polyglot SBOM'
        assert 'pkg:golang/' in purl_str, 'No Go artifacts in polyglot SBOM'
        assert 'pkg:maven/' in purl_str, 'No Maven artifacts in polyglot SBOM'

    def test_ML01_coverage_metadata(self, polyglot_sbom_resolved):
        cov = polyglot_sbom_resolved.get('_reachable_registry_coverage')
        if cov is None:
            pytest.skip('Resolver returned original')
        assert cov['total_packages'] >= 4, \
            f"Expected >=4 packages, got {cov['total_packages']}"

    @requires_grype
    def test_ML01_grype_finds_cves_across_ecosystems(self, polyglot_sbom_resolved):
        """At least one CVE from at least two different ecosystems."""
        grype = grype_results_for(polyglot_sbom_resolved)
        ecosystems_with_cves = set()

        for m in grype.get('matches', []):
            purl = m.get('artifact', {}).get('purl', '')
            if 'pkg:pypi/' in purl:
                ecosystems_with_cves.add('python')
            elif 'pkg:npm/' in purl:
                ecosystems_with_cves.add('npm')
            elif 'pkg:golang/' in purl:
                ecosystems_with_cves.add('go')
            elif 'pkg:maven/' in purl:
                ecosystems_with_cves.add('maven')

        assert len(ecosystems_with_cves) >= 2, \
            f"Expected CVEs from >=2 ecosystems, got: {ecosystems_with_cves}"

    @requires_grype
    def test_ML01_lib_manager_polyglot_gaps(self, polyglot_result):
        """Gaps must exist and be well-formed."""
        gaps = polyglot_result.get('call_graph_gaps', [])
        for gap in gaps:
            assert 'name' in gap
            assert 'reason' in gap
            assert 'ecosystem' in gap


# ===================================================================
# Source Fetch Smoke Tests
# ===================================================================

class TestLibManagerSourceFetch:
    """Validates lib_manager runs through the full pipeline without crashes."""

    @requires_grype
    def test_python_pipeline_completes(self, python_mixed_result):
        assert python_mixed_result['metrics'] is not None

    @requires_grype
    def test_npm_pipeline_completes(self, npm_mixed_result):
        assert npm_mixed_result['metrics'] is not None

    @requires_grype
    def test_go_pipeline_completes(self, go_mixed_result):
        assert go_mixed_result['metrics'] is not None

    @requires_grype
    def test_maven_pipeline_completes(self, maven_mixed_result):
        assert maven_mixed_result['metrics'] is not None

    @requires_grype
    def test_polyglot_pipeline_completes(self, polyglot_result):
        assert polyglot_result['metrics'] is not None
        # At least some libraries should have been cloned
        libs = list(polyglot_result['libs_dir'].iterdir())
        assert len(libs) >= 1, 'No libraries were cloned in polyglot scan'
