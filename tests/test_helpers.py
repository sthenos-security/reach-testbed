#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""Shared test helpers — imported by test files directly."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional


def pkg(sbom: Dict, name: str, version: str = None) -> Dict:
    """Find an artifact in an SBOM by name (and optionally version)."""
    for a in sbom.get('artifacts', []):
        if a.get('name') == name:
            if version is None or a.get('version') == version:
                return a
    raise KeyError(
        f"{name}@{version} not found in SBOM "
        f"({len(sbom.get('artifacts', []))} artifacts)"
    )


def cves_for(grype_result: Dict, package_name: str) -> List[Dict]:
    """Extract CVE matches for a package name (substring match on artifact name)."""
    return [
        m for m in grype_result.get('matches', [])
        if package_name.lower() in m.get('artifact', {}).get('name', '').lower()
    ]


def call_graph_gap(result: Dict, name: str) -> Optional[Dict]:
    """Find a call graph gap entry by package name."""
    for g in result.get('call_graph_gaps', []):
        if g.get('name') == name:
            return g
    return None


def grype_results_for(sbom: Dict) -> Dict:
    """Run Grype against an SBOM dict, return parsed vulnerability results."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sbom, f)
        f.flush()
        tmp_path = Path(f.name)
    try:
        result = subprocess.run(
            ['grype', f'sbom:{tmp_path}', '-o', 'json', '--quiet'],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Grype failed: {result.stderr[:500]}")
        return json.loads(result.stdout)
    finally:
        tmp_path.unlink(missing_ok=True)
