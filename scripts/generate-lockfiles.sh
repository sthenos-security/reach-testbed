#!/usr/bin/env bash
# generate-lockfiles.sh — Generate missing lockfiles for testbed apps
#
# Run from reach-testbed root:  ./scripts/generate-lockfiles.sh
#
# Requires: go, mvn (Maven) on PATH
# Note: JS lockfiles were already generated. This script handles Go + Java.
#
# Canary apps intentionally LEFT without lockfiles (one per lang/framework):
#   JS:     hono-app           (no package-lock.json)
#   Go:     echo-app           (no go.sum)
#   Java:   java-callgraph-test (no resolved Maven deps — pom.xml only)
#   Kotlin: kotlin-app         (no gradle.lockfile)

set -euo pipefail

TESTBED_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "=== REACHABLE Testbed — Lockfile Generator ==="
echo "Root: $TESTBED_ROOT"
echo ""

# ─── Go apps: generate go.sum via 'go mod tidy' ─────────────────
GO_APPS=(
    "gin-app"
    "signal-matrix/go"
    # echo-app is the Go canary — intentionally NO go.sum
)

for app in "${GO_APPS[@]}"; do
    dir="$TESTBED_ROOT/$app"
    if [ -f "$dir/go.mod" ]; then
        echo "[Go] $app — running go mod tidy..."
        (cd "$dir" && go mod tidy 2>&1) || echo "  ⚠ go mod tidy failed for $app"
        if [ -f "$dir/go.sum" ]; then
            echo "  ✓ go.sum generated ($(wc -l < "$dir/go.sum") lines)"
        else
            echo "  ✗ go.sum NOT generated"
        fi
    else
        echo "[Go] $app — SKIP: no go.mod"
    fi
done

echo ""

# ─── Java (Maven): generate resolved dependency tree ─────────────
# For Maven projects, Syft reads pom.xml directly but needs the local
# .m2 repo populated to resolve transitive deps accurately.
# We run 'mvn dependency:resolve' to populate ~/.m2/repository.
MAVEN_APPS=(
    "signal-matrix/java"
    # java-callgraph-test is the Java canary — no resolved deps
)

for app in "${MAVEN_APPS[@]}"; do
    dir="$TESTBED_ROOT/$app"
    if [ -f "$dir/pom.xml" ]; then
        echo "[Maven] $app — running mvn dependency:resolve..."
        (cd "$dir" && mvn dependency:resolve -q 2>&1) || echo "  ⚠ mvn dependency:resolve failed for $app"
        echo "  ✓ Maven deps resolved to ~/.m2/repository"
    else
        echo "[Maven] $app — SKIP: no pom.xml"
    fi
done

echo ""

# ─── Summary ─────────────────────────────────────────────────────
echo "=== Canary apps (intentionally NO lockfile) ==="
echo "  JS:     hono-app           — no package-lock.json"
echo "  Go:     echo-app           — no go.sum"
echo "  Java:   java-callgraph-test — no resolved Maven deps"
echo "  Kotlin: kotlin-app         — no gradle.lockfile"
echo ""
echo "Done. Re-run 'reachctl scan' to see lockfile warnings for canary apps."
