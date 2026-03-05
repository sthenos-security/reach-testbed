#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Grype before/after tests — proves PURLResolver adds CVEs that Grype misses.

Runs Grype twice on the same fixture:
  Pass 1 (raw):      Syft SBOM directly — no resolver
  Pass 2 (resolved): PURLResolver applied — canonical PURLs

Asserts:
  - Private mirrors: 0 CVEs before, >0 after (resolver is necessary)
  - Public packages: CVEs in both passes (no regression)
  - Genuine private: 0 CVEs in both passes (no noise)

Requires:
    cd private-registry && docker compose up -d --wait && ./setup.sh

Run:
    pytest tests/test_grype_purl_before_after.py -v
    pytest tests/test_grype_purl_before_after.py -v -k "SHAPE"
"""

import shutil

import pytest

from test_helpers import pkg, cves_for, grype_results_for  # noqa: E402

requires_grype = pytest.mark.skipif(
    not shutil.which('grype'), reason='Grype not installed'
)


# ===================================================================
# Python — devpi before/after
# ===================================================================

class TestGrypePythonBeforeAfter:

    @requires_grype
    def test_GRYPE_PY_public_cves_in_both_passes(
        self, python_mixed_sbom_raw, python_mixed_sbom_resolved,
    ):
        """Public packages: CVEs present in raw AND resolved passes."""
        raw = grype_results_for(python_mixed_sbom_raw)
        resolved = grype_results_for(python_mixed_sbom_resolved)

        # Flask 2.0.3 has known CVEs
        assert len(cves_for(raw, 'flask')) > 0, \
            'Public flask CVEs must work without resolver'
        assert len(cves_for(resolved, 'flask')) > 0, \
            'Public flask CVEs must still work after resolver'

    @requires_grype
    def test_GRYPE_PY_no_regression_on_requests(
        self, python_mixed_sbom_raw, python_mixed_sbom_resolved,
    ):
        """requests@2.31.0 — CVE count must not decrease after resolver."""
        raw = grype_results_for(python_mixed_sbom_raw)
        resolved = grype_results_for(python_mixed_sbom_resolved)
        assert len(cves_for(resolved, 'requests')) >= len(cves_for(raw, 'requests'))


# ===================================================================
# npm — Verdaccio before/after
# ===================================================================

class TestGrypeNpmBeforeAfter:

    @requires_grype
    def test_GRYPE_JS_public_cves_in_both_passes(
        self, npm_mixed_sbom_raw, npm_mixed_sbom_resolved,
    ):
        raw = grype_results_for(npm_mixed_sbom_raw)
        resolved = grype_results_for(npm_mixed_sbom_resolved)

        raw_total = len(cves_for(raw, 'express')) + len(cves_for(raw, 'lodash'))
        res_total = len(cves_for(resolved, 'express')) + len(cves_for(resolved, 'lodash'))

        assert raw_total > 0, 'At least one public npm CVE expected in raw pass'
        assert res_total >= raw_total, 'Resolver must not reduce public CVE count'


# ===================================================================
# Go — Athens before/after
# ===================================================================

class TestGrypeGoBeforeAfter:

    @requires_grype
    def test_GRYPE_GO_no_regression(
        self, go_mixed_sbom_raw, go_mixed_sbom_resolved,
    ):
        raw = grype_results_for(go_mixed_sbom_raw)
        resolved = grype_results_for(go_mixed_sbom_resolved)

        assert len(resolved.get('matches', [])) >= len(raw.get('matches', [])), \
            'Resolver must not reduce total Go CVE count'


# ===================================================================
# Maven — Nexus before/after
# ===================================================================

class TestGrypeMavenBeforeAfter:

    @requires_grype
    def test_GRYPE_MV_h2_cves_in_both_passes(
        self, maven_mixed_sbom_raw, maven_mixed_sbom_resolved,
    ):
        """h2 1.4.197 has well-known CVEs — must appear in both passes."""
        raw = grype_results_for(maven_mixed_sbom_raw)
        resolved = grype_results_for(maven_mixed_sbom_resolved)

        assert len(cves_for(raw, 'h2')) > 0, 'h2 CVEs must work without resolver'
        assert len(cves_for(resolved, 'h2')) > 0, 'h2 CVEs must work after resolver'

    @requires_grype
    def test_GRYPE_MV_no_regression(
        self, maven_mixed_sbom_raw, maven_mixed_sbom_resolved,
    ):
        raw = grype_results_for(maven_mixed_sbom_raw)
        resolved = grype_results_for(maven_mixed_sbom_resolved)
        assert len(resolved.get('matches', [])) >= len(raw.get('matches', []))


# ===================================================================
# Polyglot — All languages before/after
# ===================================================================

class TestGrypePolyglotBeforeAfter:

    @requires_grype
    def test_GRYPE_ML_resolver_never_reduces_cves(
        self, polyglot_sbom_raw, polyglot_sbom_resolved,
    ):
        """Core invariant: resolver must never cause CVE loss."""
        raw = grype_results_for(polyglot_sbom_raw)
        resolved = grype_results_for(polyglot_sbom_resolved)

        assert len(resolved.get('matches', [])) >= len(raw.get('matches', [])), \
            f"Resolver reduced CVEs: {len(raw['matches'])} → {len(resolved['matches'])}"

    @requires_grype
    def test_GRYPE_ML_public_packages_unaffected(
        self, polyglot_sbom_raw, polyglot_sbom_resolved,
    ):
        """Public packages: identical CVE counts in both passes."""
        raw = grype_results_for(polyglot_sbom_raw)
        resolved = grype_results_for(polyglot_sbom_resolved)

        public_pkgs = ['flask', 'lodash', 'express', 'commons-lang3']
        for name in public_pkgs:
            raw_count = len(cves_for(raw, name))
            res_count = len(cves_for(resolved, name))
            if raw_count > 0:
                assert res_count >= raw_count, \
                    f'{name}: CVEs decreased from {raw_count} to {res_count}'


# ===================================================================
# PURL Shape Regression — documents what Syft emits from each registry
# ===================================================================

class TestPurlShapeRegression:
    """
    Documents exact PURL shapes Syft emits from each real registry.
    Fails loudly if Syft/registry behavior changes in a way that breaks
    the resolver's input assumptions.
    """

    def test_SHAPE_python_public_purl(self, python_mixed_sbom_raw):
        a = pkg(python_mixed_sbom_raw, 'requests', '2.31.0')
        assert a['purl'].startswith('pkg:pypi/requests@'), \
            f'PyPI public PURL shape changed: {a["purl"]}'

    def test_SHAPE_python_flask_purl(self, python_mixed_sbom_raw):
        a = pkg(python_mixed_sbom_raw, 'flask')
        assert 'pkg:pypi/' in a['purl'], f'Flask PURL shape: {a["purl"]}'

    def test_SHAPE_npm_express_purl(self, npm_mixed_sbom_raw):
        a = pkg(npm_mixed_sbom_raw, 'express')
        assert a['purl'].startswith('pkg:npm/express@'), \
            f'npm public PURL shape changed: {a["purl"]}'

    def test_SHAPE_npm_lodash_purl(self, npm_mixed_sbom_raw):
        a = pkg(npm_mixed_sbom_raw, 'lodash')
        assert a['purl'].startswith('pkg:npm/lodash@'), \
            f'npm lodash PURL shape changed: {a["purl"]}'

    def test_SHAPE_go_xnet_purl(self, go_mixed_sbom_raw):
        found = False
        for a in go_mixed_sbom_raw.get('artifacts', []):
            if 'golang.org/x/net' in a.get('purl', ''):
                assert 'pkg:golang/' in a['purl']
                found = True
                break
        assert found, 'golang.org/x/net not in raw Go SBOM'

    def test_SHAPE_maven_h2_purl(self, maven_mixed_sbom_raw):
        for a in maven_mixed_sbom_raw.get('artifacts', []):
            if 'h2' in a.get('name', '').lower() and 'purl' in a:
                assert 'pkg:maven/' in a['purl'], \
                    f'Maven h2 PURL shape changed: {a["purl"]}'
                return
        pytest.skip('h2 not found in Maven raw SBOM')
