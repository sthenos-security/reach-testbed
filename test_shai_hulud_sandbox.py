#!/usr/bin/env python3
"""
End-to-end test: Can the sandbox detect shai-hulud?

This script exercises the full detection pipeline:
  1. detect_local_packages_with_hooks() → finds shai-hulud in the repo
  2. test_local_package() → runs it in the sandbox
  3. Verdict + attack chain summary

Run from: reach-testbed/
Requires: Colima running (macOS) or Docker (Linux)
"""

import sys
import json
import logging
from pathlib import Path

# Add reach-core to path
sys.path.insert(0, str(Path(__file__).parent.parent / "reach-core"))

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)
logger = logging.getLogger(__name__)

def main():
    print("=" * 70)
    print("  SHAI-HULUD SANDBOX DETECTION TEST")
    print("=" * 70)
    print()
    
    # =========================================================================
    # Step 1: Detect local packages with install hooks
    # =========================================================================
    print("[Step 1] Scanning for local packages with install hooks...")
    print(f"  Repo: {Path(__file__).parent}")
    print()
    
    from reachable.sandbox.runner import (
        detect_local_packages_with_hooks,
        test_local_packages,
        generate_attack_chain_summary,
        SandboxRunner,
    )
    
    repo_dir = str(Path(__file__).parent)
    local_packages = detect_local_packages_with_hooks(repo_dir)
    
    if not local_packages:
        print("  ❌ No local packages with install hooks found!")
        print("  Expected to find shai-hulud-simulation/")
        sys.exit(1)
    
    print(f"  ✅ Found {len(local_packages)} local package(s):")
    for pkg in local_packages:
        print(f"     {pkg.ecosystem}: {pkg.name} v{pkg.version}")
        print(f"       Path:  {pkg.path}")
        print(f"       Hooks: {', '.join(pkg.hooks)}")
        print(f"       Risk:  {pkg.risk_reason}")
    print()
    
    # =========================================================================
    # Step 2: Check Docker/Colima availability
    # =========================================================================
    print("[Step 2] Checking sandbox prerequisites...")
    
    try:
        import docker
        print("  ✅ Docker SDK installed")
    except ImportError:
        print("  ❌ Docker SDK not installed: pip install docker")
        sys.exit(1)
    
    runner = SandboxRunner(timeout=60)
    
    if not runner.is_available():
        print("  ❌ Docker daemon not running")
        print("  Start Colima: colima start --cpu 2 --memory 4")
        sys.exit(1)
    print("  ✅ Docker daemon running")
    
    if not runner.ensure_image():
        print("  ❌ Sandbox image not available (build failed?)")
        sys.exit(1)
    print("  ✅ Sandbox image ready")
    print()
    
    # =========================================================================
    # Step 3: Run sandbox on shai-hulud
    # =========================================================================
    shai_hulud = local_packages[0]  # Should be shai-hulud-simulation
    
    print(f"[Step 3] Running sandbox on: {shai_hulud.name}")
    print(f"  Command: npm install /work/local-pkg/")
    print(f"  Network: disabled")
    print(f"  Filesystem: read-only (+ tmpfs)")
    print(f"  Package mount: {shai_hulud.path} → /work/local-pkg/ (ro)")
    print(f"  Timeout: {runner.timeout}s")
    print()
    
    result = runner.test_local_package(shai_hulud)
    
    # =========================================================================
    # Step 4: Display results
    # =========================================================================
    print("=" * 70)
    print("  RESULTS")
    print("=" * 70)
    print()
    
    verdict_icons = {
        "CLEAN": "✅", "INFO": "ℹ️",
        "WARNING": "⚠️", "CRITICAL": "🚨", "ERROR": "❌"
    }
    icon = verdict_icons.get(result.verdict.value, "?")
    
    print(f"  Verdict:    {icon} {result.verdict.value}")
    print(f"  Package:    {result.package} ({result.ecosystem})")
    print(f"  Exit code:  {result.exit_code}")
    print(f"  Duration:   {result.duration_ms}ms")
    
    if result.error:
        print(f"  Error:      {result.error}")
    
    if result.capability_score is not None:
        print(f"  Capability: {result.capability_score}/100")
    
    # Attack chain summary
    if result.metrics and result.metrics.get("attack_chain_summary"):
        print()
        print(f"  Attack Chain: {result.metrics['attack_chain_summary']}")
    
    # Events
    print()
    print(f"  Events captured: {len(result.events or [])}")
    if result.events:
        # Group by event type
        event_types = {}
        for e in result.events:
            etype = e.get("event", "unknown")
            event_types[etype] = event_types.get(etype, 0) + 1
        
        for etype, count in sorted(event_types.items(), key=lambda x: -x[1]):
            print(f"    {etype}: {count}")
    
    # Findings
    print()
    print(f"  Findings: {len(result.findings or [])}")
    if result.findings:
        for f in result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_icon = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            print(f"    {sev_icon} [{sev}] {f.rule}: {f.description}")
            if f.evidence:
                evidence_str = json.dumps(f.evidence, indent=6) if isinstance(f.evidence, dict) else str(f.evidence)
                # Truncate long evidence
                if len(evidence_str) > 200:
                    evidence_str = evidence_str[:200] + "..."
                print(f"      Evidence: {evidence_str}")
    
    # Raw events dump for debugging
    print()
    print("-" * 70)
    print("  RAW EVENTS (for debugging)")
    print("-" * 70)
    for i, e in enumerate(result.events or []):
        print(f"  [{i}] {json.dumps(e, indent=4)}")
    
    print()
    print("=" * 70)
    if result.verdict.value == "CRITICAL":
        print("  🚨 SHAI-HULUD DETECTED — sandbox works!")
    elif result.verdict.value in ("WARNING", "INFO"):
        print("  ⚠️  PARTIAL DETECTION — sandbox needs tuning")
    elif result.verdict.value == "CLEAN":
        print("  ❌ NOT DETECTED — detection gap! See events above.")
    else:
        print(f"  ❌ {result.verdict.value} — check errors above")
    print("=" * 70)
    
    return 0 if result.verdict.value == "CRITICAL" else 1


if __name__ == "__main__":
    sys.exit(main())
