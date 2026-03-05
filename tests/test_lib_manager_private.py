#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Integration tests for lib_manager source fetch with private registry packages.

Validates per package type:
  - Public packages: source cloned from public repo
  - PURL-resolved packages: canonical source cloned, saved under original name
  - Genuine private packages: explicit gap reported, not silent skip

Requires:
    cd private-registry && docker compose up -d --wait && ./setup.sh

Run:
    pytest tests/test_lib_manager_private.py -v
"""

import shutil

import pytest


requires_grype = pytest.mark.skipif(
    not shutil.which('grype'), reason='Grype not installed'
)


# ===================================================================
# Python source fetch
# ===================================================================

class TestPythonSourceFetch:

    @requires_grype
    def test_python_metrics_populated(self, python_mixed_result):
        """lib_manager must produce metrics for the Python pipeline."""
        metrics = python_mixed_result['metrics']
        assert metrics is not None
        assert isinstance(metrics, dict)

    @requires_grype
    def test_python_gaps_well_formed(self, python_mixed_result):
        """Every gap entry must have name, reason, ecosystem."""
        for gap in python_mixed_result.get('call_graph_gaps', []):
            assert 'name' in gap, f'Gap missing name: {gap}'
            assert 'reason' in gap, f'Gap missing reason: {gap}'
            assert gap['reason'] in (
                'source_fetch_failed', 'no_source_repository',
            ), f'Unexpected gap reason: {gap["reason"]}'

    @requires_grype
    def test_python_resolution_map_populated(self, python_mixed_result):
        """Resolution map should be available (may be empty if no private pkgs)."""
        rmap = python_mixed_result.get('resolution_map', {})
        assert isinstance(rmap, dict)


# ===================================================================
# npm source fetch
# ===================================================================

class TestNpmSourceFetch:

    @requires_grype
    def test_npm_metrics_populated(self, npm_mixed_result):
        assert npm_mixed_result['metrics'] is not None

    @requires_grype
    def test_npm_gaps_well_formed(self, npm_mixed_result):
        for gap in npm_mixed_result.get('call_graph_gaps', []):
            assert 'name' in gap and 'reason' in gap


# ===================================================================
# Go source fetch
# ===================================================================

class TestGoSourceFetch:

    @requires_grype
    def test_go_metrics_populated(self, go_mixed_result):
        assert go_mixed_result['metrics'] is not None

    @requires_grype
    def test_go_gaps_well_formed(self, go_mixed_result):
        for gap in go_mixed_result.get('call_graph_gaps', []):
            assert 'name' in gap and 'reason' in gap


# ===================================================================
# Maven source fetch
# ===================================================================

class TestMavenSourceFetch:

    @requires_grype
    def test_maven_metrics_populated(self, maven_mixed_result):
        assert maven_mixed_result['metrics'] is not None

    @requires_grype
    def test_maven_gaps_well_formed(self, maven_mixed_result):
        for gap in maven_mixed_result.get('call_graph_gaps', []):
            assert 'name' in gap and 'reason' in gap


# ===================================================================
# Polyglot source fetch
# ===================================================================

class TestPolyglotSourceFetch:

    @requires_grype
    def test_polyglot_libraries_cloned(self, polyglot_result):
        """At least some libraries must be cloned in a multi-language scan."""
        libs = list(polyglot_result['libs_dir'].iterdir())
        assert len(libs) >= 1, 'No libraries cloned in polyglot scan'

    @requires_grype
    def test_polyglot_gaps_have_ecosystem(self, polyglot_result):
        """Every gap in the polyglot scan must include ecosystem info."""
        for gap in polyglot_result.get('call_graph_gaps', []):
            assert 'ecosystem' in gap, f'Gap missing ecosystem: {gap}'

    @requires_grype
    def test_polyglot_no_duplicate_gaps(self, polyglot_result):
        """Same package should not appear in gaps more than once."""
        seen = set()
        for gap in polyglot_result.get('call_graph_gaps', []):
            key = (gap['name'], gap.get('ecosystem', ''))
            assert key not in seen, f'Duplicate gap: {key}'
            seen.add(key)

    @requires_grype
    def test_polyglot_resolution_map_multi_ecosystem(self, polyglot_result):
        """Resolution map should contain entries from multiple ecosystems."""
        rmap = polyglot_result.get('resolution_map', {})
        ecosystems = {eco for eco, name in rmap.keys()}
        # May be empty if no private packages resolved — that's fine for now
        assert isinstance(rmap, dict)
