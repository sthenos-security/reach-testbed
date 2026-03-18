# REACHABLE CI/CD Benchmark — Design Document

## Goal

Run four security scanners in a single GitHub Actions workflow against `reach-testbed`, feed all output into Enzo, and produce a gap-analysis comparing findings, noise, and signal coverage.

Scanners: **Dependabot**, **Trivy**, **Claude Code Security Review**, **REACHABLE**

All four run natively in GitHub Actions. No desktop tooling required.

---

## Why These Four

| Tool | Strength | Blind Spots |
|------|----------|-------------|
| **Dependabot** | GitHub-native SCA, auto-PRs for upgrades | No SAST, no reachability, no secrets/DLP/AI |
| **Trivy** | Fast SCA + IaC + secrets, wide language support | No reachability, no SAST code analysis, no AI/LLM |
| **Claude Code** | AI semantic analysis, cross-file data flow, catches bugs rule-based tools miss | No SCA (CVEs), no structured SARIF, no reachability tagging |
| **REACHABLE** | Multi-signal (8 types), reachability, AI-verified, supply chain + malware | Newer tool — benchmark validates coverage claims |

Together they represent the three generations of AppSec tooling: rule-based SCA (Dependabot/Trivy), AI SAST (Claude Code), and AI-reachability (REACHABLE). The benchmark shows where each adds value and where they overlap.

---

## Architecture

```
reach-testbed/
├── .github/workflows/
│   ├── validate.yml                 # existing — REACHABLE-only CI
│   └── benchmark.yml                # NEW — multi-scanner benchmark
├── benchmark/
│   ├── scripts/
│   │   ├── collect-dependabot.sh    # Pull Dependabot alerts via gh api
│   │   ├── normalize-claude.py      # Convert Claude JSON → enzo format
│   │   └── generate-report.py       # Build comparison markdown
│   ├── results/                     # gitignored — raw scanner output
│   └── reports/                     # gitignored — gap analysis output
└── ... (existing testbed code)
```

---

## Workflow: `.github/workflows/benchmark.yml`

```yaml
name: Security Benchmark
on:
  workflow_dispatch:
    inputs:
      reachable_version:
        description: "REACHABLE version (e.g., 1.0.0b35 or latest)"
        default: "latest"
      run_claude:
        description: "Run Claude Code Security Review"
        type: boolean
        default: true
      run_trivy:
        description: "Run Trivy"
        type: boolean
        default: true

permissions:
  contents: read
  pull-requests: write
  security-events: write    # for SARIF uploads

jobs:
  # ─────────────────────────────────────────────
  # Job 1: Dependabot (always-on, pulls existing alerts)
  # ─────────────────────────────────────────────
  dependabot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Pull Dependabot alerts
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh api /repos/${{ github.repository }}/dependabot/alerts \
            --paginate -q '.[]' > benchmark/results/dependabot.json

      - uses: actions/upload-artifact@v4
        with:
          name: dependabot-results
          path: benchmark/results/dependabot.json

  # ─────────────────────────────────────────────
  # Job 2: Trivy
  # ─────────────────────────────────────────────
  trivy:
    if: ${{ inputs.run_trivy }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy (filesystem scan)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          format: sarif
          output: benchmark/results/trivy.sarif
          severity: CRITICAL,HIGH,MEDIUM,LOW

      - name: Run Trivy (secrets)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          format: json
          output: benchmark/results/trivy-secrets.json
          scanners: secret

      - uses: actions/upload-artifact@v4
        with:
          name: trivy-results
          path: benchmark/results/trivy*

  # ─────────────────────────────────────────────
  # Job 3: Claude Code Security Review
  # ─────────────────────────────────────────────
  claude:
    if: ${{ inputs.run_claude }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - uses: anthropics/claude-code-security-review@main
        id: claude-scan
        with:
          claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
          comment-pr: false
          upload-results: true
          claude-model: claude-opus-4-6
          claudecode-timeout: 30
          exclude-directories: "node_modules,benchmark,results,.git"

      - name: Copy results
        run: |
          cp "${{ steps.claude-scan.outputs.results-file }}" \
            benchmark/results/claude.json

      - uses: actions/upload-artifact@v4
        with:
          name: claude-results
          path: benchmark/results/claude.json

  # ─────────────────────────────────────────────
  # Job 4: REACHABLE (single scan with AI)
  # ─────────────────────────────────────────────
  reachable:
    runs-on: ubuntu-latest
    env:
      GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    steps:
      - uses: actions/checkout@v4

      - name: Install REACHABLE
        run: |
          curl -fsSL https://raw.githubusercontent.com/sthenos-security/reach-dist/main/install.sh \
            | bash -s -- --version "${{ inputs.reachable_version }}"
          export PATH="$HOME/.reachable/venv/bin:$PATH"
          reachctl doctor

      - name: Scan with AI reachability
        run: |
          export PATH="$HOME/.reachable/venv/bin:$PATH"
          reachctl scan . --ai-enhance --ci --fail-on none
          cp ~/.reachable/scans/latest/repo.db benchmark/results/reachable.db

      - name: Export SARIF
        run: |
          export PATH="$HOME/.reachable/venv/bin:$PATH"
          reachctl export --format sarif -o benchmark/results/reachable.sarif

      - uses: actions/upload-artifact@v4
        with:
          name: reachable-results
          path: benchmark/results/reachable*

  # ─────────────────────────────────────────────
  # Job 5: Enzo Compare (runs after all scanners)
  # ─────────────────────────────────────────────
  compare:
    needs: [dependabot, trivy, claude, reachable]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install REACHABLE
        run: |
          curl -fsSL https://raw.githubusercontent.com/sthenos-security/reach-dist/main/install.sh \
            | bash -s -- --version "${{ inputs.reachable_version }}"
          export PATH="$HOME/.reachable/venv/bin:$PATH"

      - uses: actions/download-artifact@v4
        with:
          path: benchmark/results/
          merge-multiple: true

      - name: Restore REACHABLE scan baseline
        run: |
          export PATH="$HOME/.reachable/venv/bin:$PATH"
          # Copy the reachable.db so enzo has the baseline to compare against
          mkdir -p ~/.reachable/scans/latest
          cp benchmark/results/reachable.db ~/.reachable/scans/latest/repo.db

      - name: Enzo ingest — Dependabot
        if: hashFiles('benchmark/results/dependabot.json') != ''
        run: |
          export PATH="$HOME/.reachable/venv/bin:$PATH"
          reachctl enzo ingest --tool dependabot \
            --file benchmark/results/dependabot.json \
            --compare --output benchmark/reports/vs-dependabot.md

      - name: Enzo ingest — Trivy
        if: hashFiles('benchmark/results/trivy.sarif') != ''
        run: |
          export PATH="$HOME/.reachable/venv/bin:$PATH"
          reachctl enzo ingest --tool trivy \
            --file benchmark/results/trivy.sarif \
            --compare --output benchmark/reports/vs-trivy.md

      - name: Enzo ingest — Claude Code
        if: hashFiles('benchmark/results/claude.json') != ''
        run: |
          export PATH="$HOME/.reachable/venv/bin:$PATH"
          reachctl enzo ingest --tool claude \
            --file benchmark/results/claude.json \
            --compare --output benchmark/reports/vs-claude.md

      - name: Generate summary report
        run: |
          export PATH="$HOME/.reachable/venv/bin:$PATH"
          reachctl enzo gap-analysis \
            --output benchmark/reports/gap-analysis.md

      - uses: actions/upload-artifact@v4
        with:
          name: benchmark-report
          path: benchmark/reports/
```

---

## What Each Scanner Sees

A preview of what the benchmark will reveal, based on the testbed's known content:

```
                         Dependabot  Trivy  Claude Code  REACHABLE
─────────────────────────────────────────────────────────────────
CVE / SCA                    ✅        ✅       ❌          ✅
  + reachability             ❌        ❌       ❌          ✅
CWE / SAST                   ❌        ❌       ✅          ✅
  + reachability             ❌        ❌       ❌          ✅
Secrets                      ❌        ✅       ✅          ✅
DLP / PII                    ❌        ❌       ⚠️          ✅
AI / LLM (OWASP Top 10)     ❌        ❌       ⚠️          ✅
Malware (behavioral)         ❌        ❌       ❌          ✅
Supply Chain attacks         ❌        ❌       ⚠️          ✅
IaC / Config                 ❌        ✅       ❌          ✅
Auto-fix PRs                 ✅        ❌       ❌          ✅ (enzo)
─────────────────────────────────────────────────────────────────
⚠️ = may detect via semantic analysis, not a dedicated scanner
```

---

## Enzo Ingest: What Exists vs. What's Needed

| Scanner | Enzo Ingest | Status | Format |
|---------|-------------|--------|--------|
| Dependabot | `ingest/dependabot.py` | ✅ exists | GitHub API JSON |
| Trivy | `ingest/trivy.py` | ✅ exists | SARIF |
| Claude Code | `ingest/claude.py` | ❌ **needs new normalizer** | JSON (schema TBD) |
| REACHABLE | native (repo.db) | ✅ baseline | SQLite |

### Claude Code normalizer (`ingest/claude.py`)

The Claude Code Security Review action outputs a JSON results file. The normalizer needs to:

1. Parse the Claude JSON results (findings array with file, line, description, severity)
2. Map each finding to an `ExternalFinding` with `finding_type` (cwe, secret, etc.)
3. Attempt CWE ID extraction from the description text
4. Normalize severity to the standard scale (critical/high/medium/low)

Estimated effort: small — the JSON structure is simple, and the mapping is straightforward once we have a sample output.

---

## Metrics

The gap-analysis report will compute:

**Per scanner:**
- Total findings (raw count)
- Findings by signal type (CVE, CWE, SECRET, etc.)
- Overlap with REACHABLE findings (matched by file + line + type)
- Unique findings (found only by this tool)
- Noise estimate (findings REACHABLE marks as NOT_REACHABLE)

**Cross-scanner:**
- Consensus findings (flagged by 3+ tools)
- Reachability breakdown of consensus findings
- Signal coverage gaps per tool
- Scan time comparison

**Key research question:** Of the findings that *only* Claude Code catches (semantic bugs, logic flaws), how many does REACHABLE also flag via CWE + reachability? This is the most interesting comparison — two AI-powered approaches from different angles.

---

## Secrets & Tokens Required

| Secret | Used By | Notes |
|--------|---------|-------|
| `GITHUB_TOKEN` | Dependabot alerts | Auto-provided by GitHub Actions |
| `CLAUDE_API_KEY` | Claude Code Security Review | Must be enabled for Claude Code usage |
| `GROQ_API_KEY` | REACHABLE `--ai-enhance` | Optional — scan works without it |
| `ANTHROPIC_API_KEY` | REACHABLE `--ai-enhance` (alt) | Optional — alternative to Groq |

---

## Running It

### Option A: Full CI/CD (recommended)

Push the testbed to GitHub, enable Dependabot, add secrets, trigger the workflow:

```
gh workflow run benchmark.yml
```

Download the report artifact when complete.

### Option B: Claude-only (quick start)

If you just want to compare Claude Code vs. REACHABLE right now:

1. Add `CLAUDE_API_KEY` to the repo secrets
2. Run the workflow with `run_trivy: false`
3. Dependabot alerts will still be pulled (zero config)
4. Compare Claude's semantic findings against REACHABLE's CWE + AI signals

### Option C: Add more scanners later

The workflow is modular — each scanner is an independent job. To add OSV-Scanner, Semgrep, Bandit, Bearer, etc., just add a new job block and a corresponding `reachctl enzo ingest` line in the compare step. The enzo SARIF normalizer handles most tools out of the box.

---

## Next Steps

1. **Create `benchmark.yml`** workflow in reach-testbed
2. **Enable Dependabot** on the reach-testbed GitHub repo (if not already)
3. **Add `CLAUDE_API_KEY`** to repo secrets
4. **Write `ingest/claude.py`** normalizer in reach-core/enzo (need a sample Claude output first)
5. **Run first benchmark** and review gap-analysis
6. **Iterate** — tune ground truth, add more scanners if needed
