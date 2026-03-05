#!/bin/bash
#
# Muad'Dib Detection Comparison
# Runs multiple security tools against the Python supply chain simulation
#
# Usage: ./run-comparison.sh [--full]
#   --full: Run actual tools (requires semgrep, guarddog, trivy, grype, reachable)
#   (default): Show expected results comparison

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  MUAD'DIB DETECTION COMPARISON (Python/pip Supply Chain Attack)${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Target: ${CYAN}muaddib-simulation/${NC}"
    echo -e "  Ecosystem: ${CYAN}pip (Python)${NC}"
    echo -e "  Attack Type: ${RED}setup.py cmdclass override → Credential Theft + Exfiltration${NC}"
    echo ""
}

print_comparison_table() {
    echo -e "${BOLD}┌──────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}│  Tool              Findings      Actionable?      Sees Attack Chain?        │${NC}"
    echo -e "${BOLD}├──────────────────────────────────────────────────────────────────────────────┤${NC}"

    # Static-only tools
    printf "  ${YELLOW}%-14s${NC} %-12s ${RED}❌${NC} %-12s ${RED}❌${NC} %s\n" "Semgrep" "4 warnings" "No (FP)" "No"
    printf "  ${YELLOW}%-14s${NC} %-12s ${RED}❌${NC} %-12s ${RED}❌${NC} %s\n" "GuardDog" "3 alerts" "No (FP)" "No"
    printf "  ${YELLOW}%-14s${NC} %-12s ${RED}❌${NC} %-12s ${RED}❌${NC} %s\n" "Trivy" "0 (blind)" "Nothing" "No"
    printf "  ${YELLOW}%-14s${NC} %-12s ${RED}❌${NC} %-12s ${RED}❌${NC} %s\n" "Grype" "0 (blind)" "Nothing" "No"

    echo -e "${BOLD}├──────────────────────────────────────────────────────────────────────────────┤${NC}"

    # REACHABLE (static + dynamic)
    printf "  ${GREEN}${BOLD}%-14s${NC} ${RED}${BOLD}%-12s${NC} ${GREEN}✅${NC} %-12s ${GREEN}✅${NC} %s\n" "REACHABLE" "1 CRITICAL" "Yes" "Full chain"

    echo -e "${BOLD}└──────────────────────────────────────────────────────────────────────────────┘${NC}"
}

print_attack_chain() {
    echo ""
    echo -e "${BOLD}ATTACK CHAIN DETECTED BY REACHABLE:${NC}"
    echo ""
    echo -e "  ${RED}[Entry]${NC} setup.py → cmdclass={'install': MaliciousInstall}"
    echo -e "     │"
    echo -e "     └──► ${YELLOW}exec(base64.b64decode(_PAYLOAD))${NC}"
    echo -e "            │"
    echo -e "            ├──► ${YELLOW}harvest_credentials()${NC} (Stage 2: File Theft)"
    echo -e "            │       • Targets: .aws/credentials, .ssh/id_rsa, .npmrc"
    echo -e "            │       • Honeypots: ${GREEN}6 files accessed → CRITICAL${NC}"
    echo -e "            │"
    echo -e "            ├──► ${YELLOW}harvest_env_vars()${NC} (Stage 3: Env Theft)"
    echo -e "            │       • Targets: AWS_ACCESS_KEY_ID, GITHUB_TOKEN, NPM_TOKEN"
    echo -e "            │       • Env shim: ${GREEN}detected → HIGH${NC}"
    echo -e "            │"
    echo -e "            └──► ${YELLOW}exfiltrate()${NC} (Stage 4: Data Exfil)"
    echo -e "                    • C2: c2.muaddib-attack.test:443"
    echo -e "                    • DNS: dns-exfil.muaddib.test"
    echo -e "                    • Network: ${GREEN}blocked → HIGH${NC}"
    echo ""
    echo -e "  ${RED}${BOLD}EXFIL CHAIN: credential read + outbound attempt = MALICIOUS${NC}"
    echo ""
}

print_static_vs_dynamic() {
    echo -e "${BOLD}WHY STATIC ANALYSIS ALONE FAILS:${NC}"
    echo ""
    echo -e "  The problem with cmdclass override detection:"
    echo ""
    echo -e "    ${GREEN}numpy${NC}          uses cmdclass  →  legitimate (C extensions)"
    echo -e "    ${GREEN}cython${NC}         uses cmdclass  →  legitimate (compiler)"
    echo -e "    ${GREEN}psycopg2${NC}       uses cmdclass  →  legitimate (PostgreSQL bindings)"
    echo -e "    ${RED}muaddib${NC}        uses cmdclass  →  ${RED}MALICIOUS (credential theft)${NC}"
    echo ""
    echo -e "  GuardDog/Semgrep cannot distinguish these. Sandbox CAN:"
    echo -e "    numpy's cmdclass → compiles C code → ${GREEN}no honeypot access${NC}"
    echo -e "    muaddib's cmdclass → reads ~/.aws → ${RED}HONEYPOT TRIGGERED${NC}"
    echo ""
}

print_verdict() {
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║${NC}  ${RED}${BOLD}VERDICT: BLOCK INSTALLATION${NC}                                             ${BOLD}║${NC}"
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║${NC}                                                                            ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}  Individual tools: ${RED}Would miss or false-positive this attack${NC}              ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}  REACHABLE:        ${GREEN}Blocks with behavioral proof from sandbox${NC}            ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}                                                                            ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}  Noise reduction:  ${GREEN}87.5%${NC} (8 raw signals → 1 correlated finding)        ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}  Key evidence:     ${GREEN}Exfil chain${NC} (honeypot read + network attempt)       ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}                                                                            ${BOLD}║${NC}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
}

run_full_comparison() {
    echo -e "${YELLOW}Running full tool comparison...${NC}"
    echo ""

    local missing_tools=()
    command -v semgrep >/dev/null 2>&1 || missing_tools+=("semgrep")
    command -v guarddog >/dev/null 2>&1 || missing_tools+=("guarddog")
    command -v trivy >/dev/null 2>&1 || missing_tools+=("trivy")
    command -v grype >/dev/null 2>&1 || missing_tools+=("grype")
    command -v reachctl >/dev/null 2>&1 || missing_tools+=("reachctl")

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}Missing tools: ${missing_tools[*]}${NC}"
        echo "Install missing tools or run without --full to see expected results."
        exit 1
    fi

    echo "Running Semgrep..."
    semgrep --config auto "$TARGET_DIR" --json > /tmp/muaddib-semgrep.json 2>/dev/null || true

    echo "Running GuardDog..."
    guarddog pypi scan "$TARGET_DIR" --output-format json > /tmp/muaddib-guarddog.json 2>/dev/null || true

    echo "Running Trivy..."
    trivy fs "$TARGET_DIR" --format json > /tmp/muaddib-trivy.json 2>/dev/null || true

    echo "Running Grype..."
    grype dir:"$TARGET_DIR" -o json > /tmp/muaddib-grype.json 2>/dev/null || true

    echo "Running REACHABLE..."
    reachctl scan "$TARGET_DIR" --output json > /tmp/muaddib-reachable.json 2>/dev/null || true

    echo ""
    echo "Results saved to /tmp/muaddib-*.json"
}

# Main
print_header

if [ "$1" == "--full" ]; then
    run_full_comparison
fi

print_comparison_table
print_attack_chain
print_static_vs_dynamic
print_verdict

echo ""
echo -e "Compare with npm attack: ${CYAN}../shai-hulud-simulation/run-comparison.sh${NC}"
echo ""
