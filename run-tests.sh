#!/bin/bash
#
# REACHABLE Test Bed - Run All Tests
#
# Usage:
#   ./run-tests.sh           # Run all tests
#   ./run-tests.sh python    # Run single test

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "REACHABLE Test Bed"
echo "========================================"
echo

# Check prerequisites
command -v reachctl >/dev/null 2>&1 || {
    echo -e "${RED}Error: reachctl not found. Install with: pip install reachable${NC}"
    exit 1
}

command -v syft >/dev/null 2>&1 || {
    echo -e "${YELLOW}Warning: syft not found. SBOM generation may fail.${NC}"
}

command -v grype >/dev/null 2>&1 || {
    echo -e "${YELLOW}Warning: grype not found. CVE scanning may fail.${NC}"
}

# Test cases to run
if [ -n "$1" ]; then
    TESTS=("$1-app" "$1")
else
    TESTS=(python-app javascript-app go-app java-maven)
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

PASSED=0
FAILED=0

for test in "${TESTS[@]}"; do
    if [ ! -d "$SCRIPT_DIR/$test" ]; then
        continue
    fi
    
    echo "----------------------------------------"
    echo "Testing: $test"
    echo "----------------------------------------"
    
    # Run scan
    mkdir -p "$RESULTS_DIR/$test"
    
    if reachctl scan "$SCRIPT_DIR/$test" --output "$RESULTS_DIR/$test" --json 2>&1; then
        echo -e "${GREEN}✓ Scan completed${NC}"
        
        # Validate results
        if [ -f "$SCRIPT_DIR/expected-results/$test.json" ]; then
            if python3 "$SCRIPT_DIR/validate.py" \
                "$RESULTS_DIR/$test/reachable-report.json" \
                "$SCRIPT_DIR/expected-results/$test.json"; then
                echo -e "${GREEN}✓ Validation passed${NC}"
                ((PASSED++))
            else
                echo -e "${RED}✗ Validation failed${NC}"
                ((FAILED++))
            fi
        else
            echo -e "${YELLOW}⚠ No expected results file${NC}"
        fi
    else
        echo -e "${RED}✗ Scan failed${NC}"
        ((FAILED++))
    fi
    
    echo
done

# Summary
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo

if [ $FAILED -gt 0 ]; then
    exit 1
fi
