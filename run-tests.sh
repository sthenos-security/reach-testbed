#!/bin/bash
#
# REACHABLE Test Bed - Run All Tests
#
# Usage:
#   ./run-tests.sh                    # Run all tests
#   ./run-tests.sh python-app         # Run single test
#   ./run-tests.sh --demo             # Run investor demo only
#   ./run-tests.sh --check            # Check prerequisites only
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Test cases
ALL_TESTS=(python-app javascript-app go-app java-maven noisy-enterprise-app)

print_banner() {
    echo ""
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}                    REACHABLE TEST BED                           ${NC}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

check_scanner() {
    local cmd=$1
    local name=$2
    
    if command -v "$cmd" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name"
        return 1
    fi
}

check_prerequisites() {
    echo -e "${BOLD}Checking prerequisites...${NC}"
    echo ""
    
    local missing=0
    
    check_scanner "syft" "syft (SBOM)" || ((missing++))
    check_scanner "grype" "grype (CVEs)" || ((missing++))
    check_scanner "semgrep" "semgrep (SAST)" || ((missing++))
    check_scanner "guarddog" "guarddog (malware)" || ((missing++))
    
    # Optional
    if command -v reachctl >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} reachctl (full integration)"
    else
        echo -e "  ${DIM}○${NC} reachctl (optional)"
    fi
    
    echo ""
    
    if [ $missing -gt 0 ]; then
        echo -e "${YELLOW}Missing $missing scanner(s). Install with:${NC}"
        echo ""
        echo "  # Syft & Grype"
        echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
        echo "  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
        echo ""
        echo "  # Semgrep & GuardDog"
        echo "  pip install semgrep guarddog"
        echo ""
        return 1
    fi
    
    echo -e "${GREEN}All prerequisites met!${NC}"
    return 0
}

run_scan() {
    local test_dir=$1
    local output_dir=$2
    local test_name=$(basename "$test_dir")
    
    mkdir -p "$output_dir"
    
    # Check if reachctl is available
    if command -v reachctl >/dev/null 2>&1; then
        echo -e "  ${CYAN}Running reachctl scan...${NC}"
        reachctl scan "$test_dir" --output "$output_dir" --format json 2>&1 || true
    else
        # Run individual scanners
        echo -e "  ${CYAN}[1/4]${NC} SBOM (syft)..."
        syft dir:"$test_dir" -o json > "$output_dir/sbom.json" 2>/dev/null || echo "{}" > "$output_dir/sbom.json"
        
        echo -e "  ${CYAN}[2/4]${NC} CVEs (grype)..."
        grype sbom:"$output_dir/sbom.json" -o json > "$output_dir/grype.json" 2>/dev/null || echo '{"matches":[]}' > "$output_dir/grype.json"
        
        echo -e "  ${CYAN}[3/4]${NC} SAST (semgrep)..."
        semgrep --config auto "$test_dir" --json > "$output_dir/semgrep.json" 2>/dev/null || echo '{"results":[]}' > "$output_dir/semgrep.json"
        
        echo -e "  ${CYAN}[4/4]${NC} Malware (guarddog)..."
        if [ -f "$test_dir/package.json" ]; then
            guarddog npm scan "$test_dir" --output-format json > "$output_dir/guarddog.json" 2>/dev/null || echo "[]" > "$output_dir/guarddog.json"
        else
            echo "[]" > "$output_dir/guarddog.json"
        fi
    fi
}

print_scan_summary() {
    local output_dir=$1
    
    # Count findings
    local cve_count=0
    local sast_count=0
    local malware_count=0
    
    if [ -f "$output_dir/grype.json" ]; then
        cve_count=$(jq '.matches | length' "$output_dir/grype.json" 2>/dev/null || echo "0")
    fi
    
    if [ -f "$output_dir/semgrep.json" ]; then
        sast_count=$(jq '.results | length' "$output_dir/semgrep.json" 2>/dev/null || echo "0")
    fi
    
    if [ -f "$output_dir/guarddog.json" ]; then
        malware_count=$(jq 'length' "$output_dir/guarddog.json" 2>/dev/null || echo "0")
    fi
    
    echo -e "  ${DIM}CVEs: $cve_count | SAST: $sast_count | Malware: $malware_count${NC}"
}

run_demo() {
    print_banner
    
    echo -e "${BOLD}Running investor demo...${NC}"
    echo ""
    
    # Stats dashboard
    echo -e "${CYAN}[1/2] Generating stats dashboard...${NC}"
    echo ""
    "$SCRIPT_DIR/generate-demo-stats.sh"
    
    # Shai-hulud demo
    echo ""
    echo -e "${CYAN}[2/2] Running Shai-Hulud comparison...${NC}"
    echo ""
    cd "$SCRIPT_DIR/shai-hulud-simulation"
    chmod +x run-comparison.sh
    ./run-comparison.sh
    
    echo ""
    echo -e "${GREEN}${BOLD}Demo complete!${NC}"
}

run_tests() {
    local tests=("$@")
    
    if [ ${#tests[@]} -eq 0 ]; then
        tests=("${ALL_TESTS[@]}")
    fi
    
    print_banner
    
    if ! check_prerequisites; then
        exit 1
    fi
    
    echo ""
    
    local passed=0
    local failed=0
    local total=${#tests[@]}
    
    for test in "${tests[@]}"; do
        local test_dir="$SCRIPT_DIR/$test"
        
        if [ ! -d "$test_dir" ]; then
            echo -e "${YELLOW}Skipping $test (not found)${NC}"
            continue
        fi
        
        echo -e "${BOLD}────────────────────────────────────────${NC}"
        echo -e "${BOLD}Testing: $test${NC}"
        echo -e "${BOLD}────────────────────────────────────────${NC}"
        
        local output_dir="$RESULTS_DIR/$test"
        
        if run_scan "$test_dir" "$output_dir"; then
            echo -e "  ${GREEN}✓ Scan completed${NC}"
            print_scan_summary "$output_dir"
            ((passed++))
        else
            echo -e "  ${RED}✗ Scan failed${NC}"
            ((failed++))
        fi
        
        echo ""
    done
    
    # Summary
    echo -e "${BOLD}════════════════════════════════════════${NC}"
    echo -e "${BOLD}SUMMARY${NC}"
    echo -e "${BOLD}════════════════════════════════════════${NC}"
    echo -e "  Passed: ${GREEN}$passed${NC}"
    echo -e "  Failed: ${RED}$failed${NC}"
    echo -e "  Results: ${CYAN}$RESULTS_DIR/${NC}"
    echo ""
    
    if [ $failed -gt 0 ]; then
        exit 1
    fi
}

# Main
case "${1:-}" in
    --demo)
        run_demo
        ;;
    --check)
        print_banner
        check_prerequisites
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS] [TEST_CASE]"
        echo ""
        echo "Options:"
        echo "  --demo     Run investor demo (stats + shai-hulud)"
        echo "  --check    Check prerequisites only"
        echo "  --help     Show this help"
        echo ""
        echo "Test cases: ${ALL_TESTS[*]}"
        ;;
    *)
        if [ -n "$1" ]; then
            run_tests "$1"
        else
            run_tests
        fi
        ;;
esac
