#!/usr/bin/env python3
"""
Weekly taint-sink pattern harvester.

Mines popular GitHub repos for taint-sink code patterns, deduplicates against
existing fixtures, and generates candidate fixture files in a staging directory
for human review before promotion to the main testbed.

Usage:
    # Full harvest (all languages, top repos)
    python harvest_patterns.py

    # Single language
    python harvest_patterns.py --lang python

    # Promote reviewed candidates to testbed
    python harvest_patterns.py --promote

    # Dry run (show what would be searched, don't write)
    python harvest_patterns.py --dry-run
"""

import argparse
import json
import os
import re
import subprocess
import sys
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent
STAGING_DIR = HERE / "staging"
EXISTING_DIR = HERE  # main fixture tree

# Repos to mine, grouped by primary language.
# Format: (owner/repo, language, [extra search terms])
REPOS = {
    "python": [
        ("django/django", ["mark_safe", "cursor.execute", "subprocess", "redirect", "HttpResponse"]),
        ("pallets/flask", ["render_template_string", "send_file", "redirect", "subprocess"]),
        ("psf/requests", ["urlopen", "Session.send"]),
        ("langchain-ai/langchain", ["exec(", "eval(", "subprocess", "cursor.execute"]),
        ("run-llama/llama_index", ["open(", "exec(", "pickle", "eval("]),
        ("microsoft/autogen", ["exec(", "subprocess", "eval("]),
        ("tiangolo/fastapi", ["subprocess", "open(", "redirect"]),
        ("encode/starlette", ["send_file", "redirect"]),
        ("apache/airflow", ["subprocess", "exec(", "cursor.execute"]),
        ("celery/celery", ["subprocess", "pickle"]),
    ],
    "go": [
        ("kubernetes/kubernetes", ["exec.Command", "os.Open", "http.Get", "yaml.Unmarshal"]),
        ("grafana/grafana", ["exec.Command", "fmt.Sprintf.*SELECT", "http.Get", "filepath.Join"]),
        ("ollama/ollama", ["exec.Command", "os.Open", "http.Get", "filepath.Join"]),
        ("go-skynet/LocalAI", ["exec.Command", "os.Open", "http.Get"]),
        ("hashicorp/terraform", ["exec.Command", "os.Open", "filepath.Join"]),
        ("hashicorp/vault", ["exec.Command", "os.Open", "http.Get"]),
        ("moby/moby", ["exec.Command", "os.Open", "filepath.Join"]),
        ("containerd/containerd", ["exec.Command", "os.Open", "filepath.Join"]),
    ],
    "java": [
        ("elastic/elasticsearch", ["Runtime.exec", "ProcessBuilder", "ObjectInputStream",
                                    "DocumentBuilderFactory", "RestClient", "String.format"]),
        ("spring-projects/spring-framework", ["Runtime.exec", "redirect:", "HttpResponse"]),
        ("spring-projects/spring-ai", ["ScriptEngine", "execute", "String.format"]),
        ("apache/kafka", ["Runtime.exec", "ProcessBuilder", "ObjectInputStream"]),
        ("apache/flink", ["Runtime.exec", "ProcessBuilder", "XMLInputFactory"]),
        ("langchain4j/langchain4j", ["ScriptEngine", "eval", "execute"]),
        ("keycloak/keycloak", ["redirect", "Runtime.exec", "XMLInputFactory"]),
    ],
    "typescript": [
        ("microsoft/vscode", ["exec(", "innerHTML", "path.join", "redirect", "eval("]),
        ("vercel/ai", ["eval(", "fetch(", "exec("]),
        ("openai/openai-node", ["fetch(", "eval("]),
        ("microsoft/TypeChat", ["exec(", "eval(", "db.run"]),
        ("nodejs/node", ["exec(", "spawn(", "eval(", "fs.readFile"]),
        ("nestjs/nest", ["exec(", "redirect", "innerHTML"]),
        ("prisma/prisma", ["$queryRaw", "$executeRaw"]),
        ("trpc/trpc", ["eval(", "exec("]),
    ],
}

# Sink patterns by CWE (used to classify discovered code)
SINK_PATTERNS = {
    "CWE-78": {
        "python": [r"subprocess\.\w+\(.*shell\s*=\s*True", r"os\.system\(", r"os\.popen\("],
        "go": [r'exec\.Command\("(?:bash|sh|cmd)"', r'exec\.CommandContext.*"-c"'],
        "java": [r"Runtime.*exec\(", r"ProcessBuilder.*\"(?:sh|bash|cmd)"],
        "typescript": [r"exec\(", r"execSync\(", r'spawn\(.*shell:\s*true'],
    },
    "CWE-89": {
        "python": [r"execute\(.*f[\"']", r'execute\(.*%.*%', r"execute\(.*\.format\("],
        "go": [r"fmt\.Sprintf.*(?:SELECT|INSERT|UPDATE|DELETE)", r'Exec\(.*\+'],
        "java": [r"executeQuery\(.*\+", r'String\.format\(.*(?:SELECT|INSERT|UPDATE|DELETE)'],
        "typescript": [r"db\.run\(.*\$\{", r"\$queryRaw.*\$\{", r"execute\(.*\+"],
    },
    "CWE-22": {
        "python": [r"open\(.*os\.path\.join", r"send_file\(.*\+", r"open\(.*request"],
        "go": [r"os\.(?:Open|ReadFile)\(.*filepath\.Join", r"os\.Open\(.*\+"],
        "java": [r"new File\(.*\+", r"Path\.resolve\(.*request"],
        "typescript": [r"fs\.read(?:File|FileSync)\(.*path\.join", r"fs\.read.*req\."],
    },
    "CWE-79": {
        "python": [r"mark_safe\(", r"render_template_string\(", r"HttpResponse\(.*<"],
        "go": [r"template\.HTML\(", r'fmt\.Fprintf\(w,.*"<'],
        "java": [r'getWriter\(\)\.print.*\+.*getParameter', r"innerHTML"],
        "typescript": [r"innerHTML\s*=", r"dangerouslySetInnerHTML", r"document\.write\("],
    },
    "CWE-918": {
        "python": [r"requests\.get\(.*request", r"urlopen\(.*request"],
        "go": [r"http\.Get\(.*request", r"http\.Post\(.*request"],
        "java": [r"RestTemplate.*getFor.*request", r"HttpURLConnection.*request"],
        "typescript": [r"fetch\(.*req\.", r"fetch\(.*request\."],
    },
    "CWE-502": {
        "python": [r"pickle\.loads?\(", r"yaml\.(?:unsafe_)?load\(", r"joblib\.load\("],
        "go": [r"gob\.NewDecoder", r"yaml\.Unmarshal"],
        "java": [r"ObjectInputStream", r"readObject\("],
        "typescript": [r"eval\(.*JSON", r"new Function\(.*parse"],
    },
    "CWE-94": {
        "python": [r"eval\(", r"exec\(", r"getattr\(.*request"],
        "go": [],
        "java": [r"ScriptEngine.*eval\(", r"Class\.forName\(.*request"],
        "typescript": [r"eval\(", r"new Function\(", r"vm\.run"],
    },
    "CWE-611": {
        "python": [r"etree\.parse\(", r"xml\.sax\.parse\("],
        "go": [],
        "java": [r"DocumentBuilderFactory", r"SAXParserFactory", r"XMLInputFactory"],
        "typescript": [],
    },
}


def gh_search_code(repo: str, query: str, per_page: int = 5) -> List[Dict]:
    """Search GitHub code via gh CLI."""
    full_query = f"repo:{repo} {query}"
    try:
        result = subprocess.run(
            ["gh", "api", "search/code", "-X", "GET",
             "-f", f"q={full_query}", "-f", f"per_page={per_page}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"  [WARN] gh search failed for {repo}/{query}: {result.stderr[:100]}")
            return []
        data = json.loads(result.stdout)
        return data.get("items", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"  [WARN] gh search error for {repo}/{query}: {e}")
        return []


def gh_fetch_file(repo: str, path: str, ref: str = "HEAD") -> Optional[str]:
    """Fetch file content from GitHub."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/contents/{path}",
             "-H", "Accept: application/vnd.github.raw+json"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def extract_function_around_line(content: str, target_line: int, lang: str) -> Optional[str]:
    """Extract the function containing the target line."""
    lines = content.split("\n")
    if target_line >= len(lines):
        return None

    # Find function start (walk backwards)
    func_start = target_line
    func_patterns = {
        "python": r"^\s*def ",
        "go": r"^func ",
        "java": r"^\s*(?:public|private|protected|static).*\w+\s*\(",
        "typescript": r"^\s*(?:export\s+)?(?:async\s+)?function\s+|^\s*(?:const|let)\s+\w+\s*=.*=>",
    }
    pat = func_patterns.get(lang, r"^\s*(?:def |func |function )")
    for i in range(target_line, max(0, target_line - 50), -1):
        if re.match(pat, lines[i]):
            func_start = i
            break

    # Take func_start to func_start + 30 lines (or next function)
    func_end = min(func_start + 30, len(lines))
    for i in range(func_start + 1, func_end):
        if re.match(pat, lines[i]):
            func_end = i
            break

    return "\n".join(lines[func_start:func_end])


def pattern_signature(code: str) -> str:
    """Generate a signature for dedup: normalize whitespace, remove comments."""
    code = re.sub(r"//.*|#.*|/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"\s+", " ", code).strip()
    return hashlib.md5(code.encode()).hexdigest()[:12]


def load_existing_signatures() -> set:
    """Load signatures of all existing fixtures for dedup."""
    sigs = set()
    for fpath in EXISTING_DIR.rglob("*"):
        if fpath.suffix in {".py", ".go", ".java", ".ts", ".js"}:
            if fpath.name in {"validate_fixtures.py", "run_taint_engine.py", "harvest_patterns.py"}:
                continue
            try:
                content = fpath.read_text(errors="replace")
                sigs.add(pattern_signature(content))
            except OSError:
                pass
    return sigs


def classify_pattern(code: str, lang: str) -> Tuple[str, str]:
    """Classify a code snippet by CWE and guess TP/TN verdict."""
    best_cwe = ""
    for cwe, lang_patterns in SINK_PATTERNS.items():
        for pat in lang_patterns.get(lang, []):
            if re.search(pat, code, re.IGNORECASE):
                best_cwe = cwe
                break
        if best_cwe:
            break

    # Heuristic verdict: if we see a sanitizer/validation near the sink, likely TN
    sanitizer_signals = [
        r"escape\(", r"sanitize", r"parameterized", r"prepared",
        r"allowlist", r"whitelist", r"startswith\(", r"HasPrefix\(",
        r"not in \w+", r"shell\s*=\s*False", r"__builtins__.*\{\}",
        r"disallow-doctype", r"SUPPORT_DTD.*false",
    ]
    has_sanitizer = any(re.search(s, code, re.IGNORECASE) for s in sanitizer_signals)
    verdict = "TRUE_NEGATIVE" if has_sanitizer else "TRUE_POSITIVE"

    return best_cwe, verdict


def generate_fixture_content(
    code: str, lang: str, cwe: str, verdict: str,
    repo: str, file_path: str, pattern_name: str,
) -> str:
    """Generate fixture file content with standard headers."""
    ext_map = {"python": "py", "go": "go", "java": "java", "typescript": "ts"}
    comment = "#" if lang == "python" else "//"

    source = "function_parameter"
    sink = "unknown"
    # Try to identify source/sink from code
    source_patterns = [
        (r"request\.(?:args|form|GET|POST|json|body)", "http_request"),
        (r"request\.getParameter", "http_request"),
        (r"r\.URL\.Query", "http_request"),
        (r"req\.(?:body|query|params)", "http_request"),
        (r"os\.(?:Args|Getenv)", "environment"),
        (r"sys\.argv", "environment"),
    ]
    for pat, src in source_patterns:
        if re.search(pat, code):
            source = src
            break

    header = f"""{comment} Fixture: {cwe} - {lang.title()}
{comment} VERDICT: {verdict}
{comment} PATTERN: {pattern_name}
{comment} SOURCE: {source}
{comment} SINK: {sink}
{comment} TAINT_HOPS: 1
{comment} NOTES: Harvested pattern - needs human review
{comment} REAL_WORLD: {repo} {file_path}
"""
    return header + "\n" + code + "\n"


def harvest_repo(repo: str, lang: str, search_terms: List[str],
                 existing_sigs: set, dry_run: bool = False) -> List[Dict]:
    """Harvest patterns from a single repo."""
    candidates = []

    for term in search_terms:
        items = gh_search_code(repo, term, per_page=3)
        for item in items:
            file_path = item.get("path", "")
            # Skip test files, vendor, generated
            if any(skip in file_path.lower() for skip in
                   ["test", "vendor", "generated", "mock", "fixture", "example", "doc/"]):
                continue

            if dry_run:
                print(f"    [DRY] Would fetch {repo}/{file_path}")
                continue

            content = gh_fetch_file(repo, file_path)
            if not content:
                continue

            # Find relevant lines
            for i, line in enumerate(content.split("\n")):
                if term.replace("\\", "") in line or re.search(re.escape(term), line):
                    snippet = extract_function_around_line(content, i, lang)
                    if not snippet or len(snippet) < 30:
                        continue

                    sig = pattern_signature(snippet)
                    if sig in existing_sigs:
                        continue

                    cwe, verdict = classify_pattern(snippet, lang)
                    if not cwe:
                        continue

                    existing_sigs.add(sig)
                    candidates.append({
                        "repo": repo,
                        "file_path": file_path,
                        "line": i,
                        "language": lang,
                        "cwe": cwe,
                        "verdict": verdict,
                        "code": snippet,
                        "signature": sig,
                        "search_term": term,
                    })
                    break  # One match per file per term

    return candidates


def write_candidates(candidates: List[Dict]) -> int:
    """Write candidate fixtures to staging directory."""
    STAGING_DIR.mkdir(exist_ok=True)
    written = 0

    for c in candidates:
        lang = c["language"]
        cwe = c["cwe"].lower().replace("-", "")
        repo_short = c["repo"].split("/")[-1]
        prefix = "tp" if c["verdict"] == "TRUE_POSITIVE" else "tn"
        sig = c["signature"][:8]

        fname_stem = f"{prefix}_{repo_short}_{sig}"
        ext = {"python": ".py", "go": ".go", "java": ".java", "typescript": ".ts"}[lang]
        fname = fname_stem + ext

        subdir = STAGING_DIR / lang / cwe
        subdir.mkdir(parents=True, exist_ok=True)
        fpath = subdir / fname

        if fpath.exists():
            continue

        pattern_name = f"{repo_short}_{c['search_term'].replace(' ', '_')}"
        content = generate_fixture_content(
            c["code"], lang, c["cwe"], c["verdict"],
            c["repo"], c["file_path"], pattern_name,
        )
        fpath.write_text(content)
        written += 1
        print(f"  STAGED: {lang}/{cwe}/{fname}  [{c['verdict']}]  from {c['repo']}")

    return written


def promote_staging():
    """Move reviewed candidates from staging/ into the main fixture tree."""
    if not STAGING_DIR.exists():
        print("No staging directory found.")
        return

    promoted = 0
    for fpath in sorted(STAGING_DIR.rglob("*")):
        if fpath.suffix not in {".py", ".go", ".java", ".ts"}:
            continue
        # Destination: same relative path under EXISTING_DIR
        rel = fpath.relative_to(STAGING_DIR)
        dest = EXISTING_DIR / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            print(f"  SKIP (exists): {rel}")
            continue
        fpath.rename(dest)
        promoted += 1
        print(f"  PROMOTED: {rel}")

    # Clean up empty staging dirs
    for d in sorted(STAGING_DIR.rglob("*"), reverse=True):
        if d.is_dir():
            try:
                d.rmdir()
            except OSError:
                pass
    try:
        STAGING_DIR.rmdir()
    except OSError:
        pass

    print(f"\nPromoted {promoted} fixtures to testbed.")
    print("Run: REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Weekly taint pattern harvester")
    parser.add_argument("--lang", choices=["python", "go", "java", "typescript"],
                        help="Harvest only this language")
    parser.add_argument("--promote", action="store_true",
                        help="Promote reviewed staging candidates to testbed")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be searched without fetching")
    parser.add_argument("--max-per-repo", type=int, default=5,
                        help="Max candidates per repo (default: 5)")
    args = parser.parse_args()

    if args.promote:
        promote_staging()
        return

    # Check gh CLI is available
    try:
        subprocess.run(["gh", "auth", "status"], capture_output=True, timeout=10)
    except FileNotFoundError:
        print("ERROR: 'gh' CLI not found. Install: https://cli.github.com/")
        print("       brew install gh && gh auth login")
        sys.exit(1)

    print(f"Taint Pattern Harvester - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"Staging directory: {STAGING_DIR}")
    print()

    existing_sigs = load_existing_signatures()
    print(f"Loaded {len(existing_sigs)} existing pattern signatures for dedup")
    print()

    languages = [args.lang] if args.lang else list(REPOS.keys())
    all_candidates = []

    for lang in languages:
        repos = REPOS.get(lang, [])
        print(f"=== {lang.upper()} ({len(repos)} repos) ===")
        for repo, terms in repos:
            print(f"  Mining {repo}...")
            candidates = harvest_repo(repo, lang, terms, existing_sigs,
                                      dry_run=args.dry_run)
            if candidates:
                all_candidates.extend(candidates[:args.max_per_repo])
        print()

    if args.dry_run:
        print(f"Dry run complete. Would search {len(all_candidates)} potential matches.")
        return

    if not all_candidates:
        print("No new patterns found.")
        return

    written = write_candidates(all_candidates)
    print(f"\n{'='*60}")
    print(f"Staged {written} candidate fixtures in {STAGING_DIR}/")
    print(f"\nNext steps:")
    print(f"  1. Review candidates: ls {STAGING_DIR}/")
    print(f"  2. Edit verdicts if needed (check VERDICT: lines)")
    print(f"  3. Delete bad candidates")
    print(f"  4. Promote: python harvest_patterns.py --promote")
    print(f"  5. Validate: REACH_CORE=~/src/reach-core python run_taint_engine.py --verbose")

    # Save harvest report
    report = {
        "timestamp": datetime.now().isoformat(),
        "candidates": len(all_candidates),
        "written": written,
        "by_language": {},
        "by_cwe": {},
    }
    for c in all_candidates:
        report["by_language"][c["language"]] = report["by_language"].get(c["language"], 0) + 1
        report["by_cwe"][c["cwe"]] = report["by_cwe"].get(c["cwe"], 0) + 1

    report_path = STAGING_DIR / "harvest_report.json"
    STAGING_DIR.mkdir(exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport: {report_path}")


if __name__ == "__main__":
    main()
