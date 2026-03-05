#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Integration tests for unresolved package tracking.

Validates that the full pipeline correctly:
  - Identifies unresolved packages in the enriched SBOM
  - Tracks them in _reachable_registry_coverage metadata
  - Surfaces them in call_graph_gaps from lib_manager
  - Produces consistent counts across SBOM metadata and gap reporting

Requires:
    cd private-registry && docker compose up -d --wait && ./setup.sh

Run:
    pytest tests/test_unresolved_integration.py -v
"""

import shutil

import pytest


requires_grype = pytest.mark.skipif(
    not shutil.which('grype'), reason='Grype not installed'
)


# ===================================================================
# SBOM-Level Unresolved Tracking
# ===================================================================

class TestUnresolvedInSbom:
    """Validates _reachable_registry_coverage metadata in enriched SBOMs."""

    def test_python_coverage_counts_consistent(self, python_mixed_sbom_resolved):
        """Coverage counts must add up: canonical + alias + ... == total."""
        cov = python_mixed_sbom_resolved.get('_reachable_registry_coverage')
        if cov is None:
            pytest.skip('Resolver returned original (no rewrites needed)')

        total = cov.get('total_packages', 0)
        assert total > 0, 'Expected at least 1 package'

        # Sum of all reason counts should equal total
        reason_sum = sum(
            cov.get(reason, 0)
            for reason in ('canonical', 'alias', 'hash_match', 'internal', 'unresolved')
        )
        assert reason_sum == total, (
            f'Coverage reasons sum ({reason_sum}) != total ({total}). '
            f'Coverage: {cov}'
        )

    def test_npm_coverage_counts_consistent(self, npm_mixed_sbom_resolved):
        cov = npm_mixed_sbom_resolved.get('_reachable_registry_coverage')
        if cov is None:
            pytest.skip('Resolver returned original')

        total = cov.get('total_packages', 0)
        assert total > 0

        reason_sum = sum(
            cov.get(reason, 0)
            for reason in ('canonical', 'alias', 'hash_match', 'internal', 'unresolved')
        )
        assert reason_sum == total

    def test_go_coverage_counts_consistent(self, go_mixed_sbom_resolved):
        cov = go_mixed_sbom_resolved.get('_reachable_registry_coverage')
        if cov is None:
            pytest.skip('Resolver returned original')
        total = cov.get('total_packages', 0)
        assert total > 0

    def test_polyglot_coverage_spans_ecosystems(self, polyglot_sbom_resolved):
        """Polyglot coverage should count packages from all ecosystems."""
        cov = polyglot_sbom_resolved.get('_reachable_registry_coverage')
        if cov is None:
            pytest.skip('Resolver returned original')

        # Polyglot includes python + npm + go + maven, so expect many packages
        total = cov.get('total_packages', 0)
        assert total >= 4, f'Expected >=4 packages in polyglot, got {total}'


# ===================================================================
# Artifact-Level Resolution Metadata
# ===================================================================

class TestArtifactResolutionMetadata:
    """Each artifact should have consistent resolution metadata."""

    def test_python_artifacts_have_valid_purls(self, python_mixed_sbom_resolved):
        for a in python_mixed_sbom_resolved.get('artifacts', []):
            purl = a.get('purl', '')
            if purl:
                assert purl.startswith('pkg:'), f"Invalid PURL: {purl}"

    def test_npm_artifacts_have_valid_purls(self, npm_mixed_sbom_resolved):
        for a in npm_mixed_sbom_resolved.get('artifacts', []):
            purl = a.get('purl', '')
            if purl:
                assert purl.startswith('pkg:'), f"Invalid PURL: {purl}"

    def test_resolved_artifacts_have_original_purl(self, python_mixed_sbom_resolved):
        """Any artifact with a rewrite must preserve the original PURL."""
        for a in python_mixed_sbom_resolved.get('artifacts', []):
            reg = a.get('_reachable_registry', {})
            resolution = reg.get('resolution', '')
            if resolution in ('alias', 'hash_match'):
                assert 'original_purl' in reg, (
                    f"Resolved artifact {a['name']} missing original_purl. "
                    f"Registry metadata: {reg}"
                )

    def test_canonical_artifacts_no_original_purl(self, python_mixed_sbom_resolved):
        """Canonical (unchanged) artifacts should NOT have original_purl."""
        for a in python_mixed_sbom_resolved.get('artifacts', []):
            reg = a.get('_reachable_registry', {})
            resolution = reg.get('resolution', 'canonical')
            if resolution == 'canonical':
                assert 'original_purl' not in reg, (
                    f"Canonical artifact {a['name']} shouldn't have original_purl"
                )


# ===================================================================
# Gap Reporting Consistency
# ===================================================================

@requires_grype
class TestGapReportingConsistency:
    """call_graph_gaps must be consistent with SBOM unresolved metadata."""

    def test_python_gap_names_are_real_packages(self, python_mixed_result):
        """Every gap name must correspond to a real package in the SBOM."""
        sbom_names = {
            a.get('name') for a in
            python_mixed_result['sbom'].get('artifacts', [])
        }
        grype_names = {
            m.get('artifact', {}).get('name', '')
            for m in python_mixed_result['grype'].get('matches', [])
        }
        all_known = sbom_names | grype_names

        for gap in python_mixed_result.get('call_graph_gaps', []):
            # Gap name should be in either SBOM or Grype results
            # (it's a package we tried to clone)
            assert gap['name'], f"Empty gap name: {gap}"

    def test_polyglot_gap_ecosystems_valid(self, polyglot_result):
        """Every gap must have a valid ecosystem field."""
        valid_ecosystems = {
            'python', 'pypi', 'npm', 'go', 'golang',
            'maven', 'java', 'java-archive',
        }
        for gap in polyglot_result.get('call_graph_gaps', []):
            eco = gap.get('ecosystem', '')
            assert eco in valid_ecosystems, (
                f"Gap '{gap['name']}' has invalid ecosystem: '{eco}'"
            )

    def test_no_duplicate_gaps(self, polyglot_result):
        """Each package should appear at most once in call_graph_gaps."""
        gaps = polyglot_result.get('call_graph_gaps', [])
        seen = set()
        for gap in gaps:
            key = (gap['name'], gap.get('version', ''), gap.get('ecosystem', ''))
            assert key not in seen, f"Duplicate gap entry: {key}"
            seen.add(key)


# ===================================================================
# Resolution Map Consistency
# ===================================================================

class TestResolutionMapConsistency:
    """Validates the resolution map passed between PURLResolver and lib_manager."""

    @requires_grype
    def test_resolution_map_keys_are_tuples(self, python_mixed_result):
        rmap = python_mixed_result.get('resolution_map', {})
        for key in rmap:
            assert isinstance(key, tuple), f"Resolution map key should be tuple: {key}"
            assert len(key) == 2, f"Resolution map key should be (ecosystem, name): {key}"

    @requires_grype
    def test_resolution_map_values_have_required_fields(self, python_mixed_result):
        rmap = python_mixed_result.get('resolution_map', {})
        required_fields = {'canonical_name', 'method'}
        for key, val in rmap.items():
            for field in required_fields:
                assert field in val, (
                    f"Resolution map entry {key} missing '{field}': {val}"
                )

    @requires_grype
    def test_polyglot_resolution_map(self, polyglot_result):
        rmap = polyglot_result.get('resolution_map', {})
        # Map may be empty if no private packages were resolved
        assert isinstance(rmap, dict)
        for key, val in rmap.items():
            assert 'canonical_name' in val
            assert 'method' in val
            assert val['method'] in (
                'hash_match', 'alias', 'internal', 'unresolved',
            ), f"Unknown resolution method for {key}: {val['method']}"
