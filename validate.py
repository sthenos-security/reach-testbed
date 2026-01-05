#!/usr/bin/env python3
"""
REACHABLE Test Bed Validator

Compares actual scan results against expected baselines.
Fails if detection rates drop below thresholds.

Usage:
    python validate.py actual.json expected.json
"""

import json
import sys
from pathlib import Path


def load_json(path: str) -> dict:
    """Load JSON file."""
    with open(path) as f:
        return json.load(f)


def validate(actual_path: str, expected_path: str) -> bool:
    """
    Validate actual results match expected baselines.
    
    Returns True if validation passes.
    """
    actual = load_json(actual_path)
    expected = load_json(expected_path)
    
    passed = True
    errors = []
    warnings = []
    
    # Check reachable CVE count
    actual_reachable = actual.get('summary', {}).get('reachable_count', 0)
    expected_reachable = expected.get('reachable_cves', {}).get('min', 0)
    
    if actual_reachable < expected_reachable:
        errors.append(
            f"Reachable CVEs: {actual_reachable} < expected minimum {expected_reachable}"
        )
        passed = False
    
    # Check unreachable CVE count (noise reduction working)
    actual_unreachable = actual.get('summary', {}).get('unreachable_count', 0)
    expected_unreachable = expected.get('unreachable_cves', {}).get('min', 0)
    
    if actual_unreachable < expected_unreachable:
        warnings.append(
            f"Unreachable CVEs: {actual_unreachable} < expected minimum {expected_unreachable}"
        )
    
    # Check specific CVEs are detected and correctly classified
    for cve_id, expected_status in expected.get('specific_cves', {}).items():
        found = False
        actual_status = None
        
        for cve in actual.get('cves', []):
            if cve.get('id') == cve_id:
                found = True
                actual_status = 'reachable' if cve.get('reachable') else 'unreachable'
                break
        
        if not found:
            errors.append(f"CVE {cve_id} not detected (expected: {expected_status})")
            passed = False
        elif actual_status != expected_status:
            errors.append(
                f"CVE {cve_id} classified as {actual_status}, expected {expected_status}"
            )
            passed = False
    
    # Check secrets detected
    actual_secrets = len(actual.get('secrets', {}).get('findings', []))
    expected_secrets = expected.get('secrets', {}).get('min', 0)
    
    if actual_secrets < expected_secrets:
        errors.append(
            f"Secrets: {actual_secrets} < expected minimum {expected_secrets}"
        )
        passed = False
    
    # Check entrypoints detected
    actual_entrypoints = actual.get('call_graph', {}).get('entrypoints_found', 0)
    expected_entrypoints = expected.get('entrypoints', {}).get('min', 0)
    
    if actual_entrypoints < expected_entrypoints:
        warnings.append(
            f"Entrypoints: {actual_entrypoints} < expected minimum {expected_entrypoints}"
        )
    
    # Print results
    print("=" * 60)
    print(f"REACHABLE Validation: {Path(actual_path).parent.name}")
    print("=" * 60)
    
    if errors:
        print("\n❌ ERRORS:")
        for e in errors:
            print(f"   - {e}")
    
    if warnings:
        print("\n⚠️  WARNINGS:")
        for w in warnings:
            print(f"   - {w}")
    
    if passed:
        print("\n✅ VALIDATION PASSED")
    else:
        print("\n❌ VALIDATION FAILED")
    
    print()
    return passed


def main():
    if len(sys.argv) != 3:
        print("Usage: python validate.py actual.json expected.json")
        sys.exit(1)
    
    actual_path = sys.argv[1]
    expected_path = sys.argv[2]
    
    if not Path(actual_path).exists():
        print(f"Error: {actual_path} not found")
        sys.exit(1)
    
    if not Path(expected_path).exists():
        print(f"Error: {expected_path} not found")
        sys.exit(1)
    
    passed = validate(actual_path, expected_path)
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
