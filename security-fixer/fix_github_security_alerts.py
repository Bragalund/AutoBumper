#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitHub Security Fix Helper (Python) using codex

Getting Started (venv)
----------------------
This script requires Python 3.8+ and Git installed on your PATH. It also needs
a GitHub Personal Access Token (PAT) via the environment variable GITHUB_TOKEN.

1) Create & activate a virtual environment
   macOS / Linux:
     python3 -m venv .venv
     source .venv/bin/activate

   Windows (PowerShell):
     py -3 -m venv .venv
     .\.venv\Scripts\Activate.ps1

2) Install dependencies
     pip install requests

3) Set your GitHub token (replace XXXX with your token)
   macOS / Linux:
     export GITHUB_TOKEN=XXXX

   Windows (PowerShell):
     setx GITHUB_TOKEN XXXX
     # Then start a new shell so the variable is available

4) Run
   - Single repo:
       python script.py --repo owner/name
   - Filter by org-wide custom property (team property):
       python script.py --org YourOrg --team-prop-key team --team-prop-value YourTeam
   - Whole org (no team property filter):
       python script.py --org YourOrg

Features
- Single repo (--repo owner/name), property-based selection (--team-prop-*), or full-org scan fallback
- Dependabot + Code Scanning alerts; --min-severity low|medium|high|critical
- Rate limiting (max 60/min) plus /rate_limit backoff
- Writes raw body of *every* GitHub API response to raw-github-response.json (last response wins)
- DEBUG logging that previews responses (truncated)
- DRY-RUN + optional --session-in-dry-run
 - Temp clone cleanup; opens a guided session in a new terminal; draft PR on changes

Requirements
- Python 3.8+
- Git installed and available in PATH
- env GITHUB_TOKEN must be set (PAT with repo/read:org/admin:repo_hook for some calls)
"""

import argparse
import datetime as dt
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import requests

# ----------------------------
# Configuration defaults
# ----------------------------
ORG = "YouOrgHere"
TEAM_PROP_KEY_DEFAULT = None        # was "team"; now optional by default
TEAM_PROP_VALUE_DEFAULT = None      # was "yourteam"; now optional by default
FINDINGS_FILE = "security-findings.md"

BLACKLIST = {
    # "owner/repo-name",
}

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_MIN_SEVERITY = "high"

# Rate-limit guard (soft cap)
MIN_INTERVAL_SEC = 1.1  # keep comfortably under 60/min


# ----------------------------
# Utilities
# ----------------------------
def now_iso() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_branch(name: str) -> str:
    s = re.sub(r"\s+", "-", name.strip())
    s = re.sub(r"[^A-Za-z0-9._-]", "-", s)
    s = s.strip("-")
    return s or "sec-fix-update"


def trim_md_cell(text: str, limit: int = 400) -> str:
    text = text.replace("|", "-").replace("\n", " ")
    return (text[: limit - 1] + "…") if len(text) > limit else text


# ----------------------------
# HTTP / GitHub client
# ----------------------------
@dataclass
class GHClient:
    token: str
    base_url: str = "https://api.github.com"
    session: requests.Session = field(default_factory=requests.Session)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("gh"))
    last_call_ts: float = 0.0
    api_log_file: Optional[str] = None

    def __post_init__(self):
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "sec-fix-helper/1.0",
            }
        )

    def _sleep_if_needed(self):
        elapsed = time.time() - self.last_call_ts
        if elapsed < MIN_INTERVAL_SEC:
            to_sleep = MIN_INTERVAL_SEC - elapsed
            self.logger.debug("Rate limit guard: sleeping %.2fs", to_sleep)
            time.sleep(to_sleep)

    def _write_raw(self, endpoint: str, page: Optional[int], body: bytes):
        # Save LAST raw body to a fixed file name
        path = "raw-github-response.json"
        try:
            data = body.decode("utf-8", errors="ignore")
            # Try pretty print if JSON-ish
            try:
                js = json.loads(data)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(js, f, indent=2, ensure_ascii=False)
            except Exception:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(data)
            self.logger.debug(
                "Raw GitHub response written to %s (endpoint=%s page=%s size=%d)",
                path,
                endpoint,
                page,
                len(body),
            )
        except Exception as e:
            self.logger.warning("Failed to write raw body: %s", e)

        # Optional append full dump
        if self.api_log_file:
            try:
                with open(self.api_log_file, "a", encoding="utf-8") as f:
                    f.write(
                        f"===== {now_iso()} | {endpoint} | page={page} =====\n{body.decode('utf-8', 'ignore')}\n\n"
                    )
            except Exception:
                pass

    def _log_preview(self, endpoint: str, page: Optional[int], status: int, body: bytes):
        preview = body[:2048].decode("utf-8", errors="ignore")
        self.logger.debug(
            "API RESP (%s page=%s rc=%s) PREVIEW:\n%s%s",
            endpoint,
            page,
            status,
            preview,
            "\n...(truncated)" if len(body) > 2048 else "",
        )

    def _rate_limit_backoff(self):
        # Fallback backoff using /rate_limit
        self.logger.warning("GitHub API rate-limited. Checking /rate_limit…")
        try:
            r = self.session.get(f"{self.base_url}/rate_limit", timeout=15)
            self.last_call_ts = time.time()
            self._write_raw("/rate_limit", 1, r.content)
            self._log_preview("/rate_limit", 1, r.status_code, r.content)
            if r.ok:
                info = r.json()
                core = info.get("resources", {}).get("core", {})
                remaining = int(core.get("remaining", 1))
                reset = int(core.get("reset", 0))
                if remaining == 0 and reset:
                    wait = max(reset - int(time.time()) + 2, 5)
                    self.logger.warning("Sleeping %ss until reset…", wait)
                    time.sleep(wait)
                    return
        except Exception:
            pass
        self.logger.warning("Backing off 60s…")
        time.sleep(60)

    def get(self, endpoint: str, params: Optional[Dict[str, str]] = None, page: Optional[int] = None) -> Tuple[int, dict]:
        """
        Returns (status, json_dict or json_list). On parse error, returns (status, {}).
        Writes raw body to raw-github-response.json on every call.
        """
        self._sleep_if_needed()
        url = f"{self.base_url}{endpoint}"
        try:
            r = self.session.get(url, params=params, timeout=30)
            self.last_call_ts = time.time()
        except requests.Timeout:
            self.logger.warning("GET %s timed out; retrying once…", endpoint)
            time.sleep(2)
            r = self.session.get(url, params=params, timeout=60)
            self.last_call_ts = time.time()

        # Write raw & debug preview
        self._write_raw(endpoint, page, r.content)
        self._log_preview(endpoint, page, r.status_code, r.content)

        # Rate limit / abuse detection
        if r.status_code in (403, 429):
            text = r.text.lower()
            if "rate limit" in text or "secondary rate" in text or "abuse detection" in text:
                self._rate_limit_backoff()
                # retry once
                return self.get(endpoint, params=params, page=page)

        # Parse JSON (strip ANSI/control if any)
        body = r.content.decode("utf-8", errors="ignore")
        body = _strip_control_chars_and_bom(body)
        try:
            js = json.loads(body) if body else {}
        except Exception:
            self.logger.warning("Non-JSON response for %s", url)
            js = {}
        return r.status_code, js


def _strip_control_chars_and_bom(s: str) -> str:
    # Remove C0 control chars (keep LF)
    s = s.replace("\r", "")
    s = "".join(ch for ch in s if ch == "\n" or ord(ch) >= 32)
    # Strip UTF-8 BOM if present
    if s.startswith("\ufeff"):
        s = s.lstrip("\ufeff")
    # Trim to first JSON token
    m = re.search(r"^[ \t\r\n]*([\{\[])", s, re.M)
    if m:
        start = m.start(1)
        s = s[start:]
    return s.lstrip()


# ----------------------------
# Git helpers
# ----------------------------
def run(cmd: List[str], cwd: Optional[str] = None, check=True) -> subprocess.CompletedProcess:
    logging.getLogger("proc").debug("RUN: %s (cwd=%s)", " ".join(cmd), cwd or os.getcwd())
    return subprocess.run(cmd, cwd=cwd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def git_clone_with_token(repo_full: str, dest: str, token: str):
    owner, name = repo_full.split("/", 1)
    url = f"https://x-access-token:{token}@github.com/{owner}/{name}.git"
    run(["git", "clone", "--quiet", url, dest])


def git_has_changes(repo_dir: str) -> bool:
    cp = run(["git", "status", "--porcelain"], cwd=repo_dir, check=False)
    return bool(cp.stdout.strip())


# ----------------------------
# Data models
# ----------------------------
@dataclass
class Finding:
    repo: str
    source: str  # "dependabot" or "code-scanning"
    severity: str
    header: str
    description: str
    identifier: str = ""  # CVE/GHSA if present


# ----------------------------
# Alert collectors
# ----------------------------
def sev_ge(a: str, b: str) -> bool:
    return SEV_RANK.get(a, 0) >= SEV_RANK.get(b, 0)


def collect_dependabot(client: GHClient, repo: str, min_sev: str, findings: List[Finding], logger: logging.Logger):
    logger.info("Dependabot: scanning alerts (min: %s) for %s", min_sev, repo)
    status, data = client.get(f"/repos/{repo}/dependabot/alerts", params={"per_page": "100", "state": "open"}, page=1)
    if status != 200 or not isinstance(data, list):
        logger.warning("Dependabot: invalid response for %s", repo)
        return
    total = len(data)
    added = 0

    for a in data:
        sev = str(a.get("security_advisory", {}).get("severity") or a.get("severity") or "low").lower()
        if not sev_ge(sev, min_sev):
            continue

        advisory = a.get("security_advisory", {}) or {}
        header = advisory.get("summary") or "Dependabot alert"
        description = advisory.get("description") or ""
        ident = ""
        identifiers = advisory.get("identifiers") or []
        for idobj in identifiers:
            if idobj.get("type") == "CVE":
                ident = idobj.get("value") or ""
                break
        if not ident:
            ident = advisory.get("cve_id") or advisory.get("ghsa_id") or ""

        findings.append(
            Finding(
                repo=repo,
                source="dependabot",
                severity=sev,
                header=header,
                description=description,
                identifier=ident,
            )
        )
        added += 1

    logger.info("Dependabot: %s total=%d added(>=%s)=%d", repo, total, min_sev, added)


def collect_codescan(client: GHClient, repo: str, min_sev: str, findings: List[Finding], logger: logging.Logger):
    logger.info("CodeScan:   scanning alerts (min: %s) for %s", min_sev, repo)
    page = 1
    total_seen = 0
    added = 0
    while True:
        status, data = client.get(
            f"/repos/{repo}/code-scanning/alerts",
            params={"per_page": "100", "page": str(page), "state": "open"},
            page=page,
        )
        if status != 200 or not isinstance(data, list):
            if page == 1:
                logger.debug("CodeScan:   %s page=%d is empty/invalid", repo, page)
            break

        page_total = len(data)
        total_seen += page_total
        if page_total == 0:
            logger.debug("CodeScan:   %s page=%d is empty", repo, page)
            break

        for a in data:
            sev = str(
                a.get("rule", {}).get("security_severity_level")
                or a.get("rule", {}).get("severity")
                or "low"
            ).lower()
            sev = {"error": "critical", "warning": "medium", "note": "low"}.get(sev, sev)

            if not sev_ge(sev, min_sev):
                continue

            rule = a.get("rule", {}) or {}
            header = rule.get("description") or rule.get("name") or "Code scanning alert"
            desc = (a.get("most_recent_instance", {}) or {}).get("message", {}).get("text") or rule.get("name") or ""

            ident = ""
            for field in [rule.get("id", ""), header, desc]:
                if not field:
                    continue
                m = re.search(r"(CVE-\d{4}-[0-9A-Za-z]+)", str(field))
                if m:
                    ident = m.group(1)
                    break

            findings.append(
                Finding(
                    repo=repo,
                    source="code-scanning",
                    severity=sev,
                    header=header,
                    description=desc,
                    identifier=ident,
                )
            )
            added += 1

        if page_total < 100:
            break
        page += 1

    logger.info("CodeScan:   %s pages=%d seen=%d added(>=%s)=%d", repo, page, total_seen, min_sev, added)


# ----------------------------
# Repo resolution
# ----------------------------
def fetch_repos_for_team(client: GHClient, org: str, team_key: str, team_value: str, logger: logging.Logger) -> List[str]:
    """
    Query org repository custom properties and return repos that match props.{team_key}:{team_value}.
    Returns list of 'owner/name'
    """
    repos: List[str] = []

    query = f"props.{team_key}:{team_value}"
    status, data = client.get(
        f"/orgs/{org}/properties/values",
        params={"repository_query": query, "per_page": "100"},
        page=1,
    )
    if status != 200 or not isinstance(data, dict):
        logger.error("Failed to resolve repositories via custom property query %s (status=%s).", query, status)
        return repos

    items = data.get("repositories") or data
    if isinstance(items, list):
        for it in items:
            if not isinstance(it, dict):
                continue
            repo_meta = it.get("repository") if "repository" in it else it
            if isinstance(repo_meta, dict):
                full = repo_meta.get("full_name")
                if full:
                    repos.append(full)
    else:
        logger.warning("Unexpected payload from properties API for query %s: %r", query, type(items))

    if not repos:
        logger.error("No repositories matched custom property filter %s. Ensure the property exists.", query)
    return repos


def fetch_repos_in_org(client: GHClient, org: str, logger: logging.Logger) -> List[str]:
    """
    Fallback: list all repositories in an org.
    Returns list of 'owner/name'
    """
    repos: List[str] = []
    page = 1
    while True:
        status, data = client.get(
            f"/orgs/{org}/repos",
            params={"per_page": "100", "page": str(page), "type": "all"},
            page=page,
        )
        if status != 200 or not isinstance(data, list):
            if page == 1:
                logger.error("Failed to list repositories for org %s (status=%s).", org, status)
            break
        if not data:
            break
        for it in data:
            full = it.get("full_name")
            if full:
                repos.append(full)
        if len(data) < 100:
            break
        page += 1
    return repos


# ----------------------------
# Findings writer
# ----------------------------
def write_findings_md(findings: List[Finding], single_repo: Optional[str], min_sev: str, path: str, filter_text: Optional[str]):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Security findings (>= {min_sev})\n\n")
        if single_repo:
            f.write(f"**Repository:** `{single_repo}`\n\n")
        elif filter_text:
            f.write(f"**Filter:** {filter_text}\n\n")
        else:
            f.write("**Scope:** full-organization scan\n\n")
        f.write("| Repository | Source | Severity | Header | Description | Identifier |\n")
        f.write("|---|---|---|---|---|---|\n")
        for it in findings:
            f.write(
                "| {repo} | {src} | {sev} | {hdr} | {desc} | {id} |\n".format(
                    repo=it.repo,
                    src=it.source,
                    sev=it.severity,
                    hdr=trim_md_cell(it.header),
                    desc=trim_md_cell(it.description),
                    id=it.identifier or "",
                )
            )


# ----------------------------
# Prioritize findings
# ----------------------------
def prioritize_findings(findings: List[Finding], min_sev: str) -> List[Finding]:
    buckets = [
        ("dependabot", "critical"),
        ("code-scanning", "critical"),
        ("dependabot", "high"),
        ("code-scanning", "high"),
        ("dependabot", "medium"),
        ("code-scanning", "medium"),
        ("dependabot", "low"),
        ("code-scanning", "low"),
    ]
    min_rank = SEV_RANK[min_sev]
    prioritized: List[Finding] = []
    seen_indexes: Set[int] = set()

    for src, sev in buckets:
        if SEV_RANK[sev] < min_rank:
            continue
        for idx, it in enumerate(findings):
            if idx in seen_indexes:
                continue
            if it.source == src and it.severity == sev:
                prioritized.append(it)
                seen_indexes.add(idx)

    for idx, it in enumerate(findings):
        if idx not in seen_indexes:
            prioritized.append(it)

    return prioritized


# ----------------------------
# Terminal session
# ----------------------------
def open_new_terminal_and_wait(prompt_text: str, repo_dir: str, dry_run: bool, session_in_dry_run: bool, logger: logging.Logger):
    cmd = f"""cd {shlex_quote(repo_dir)}; \
echo {shlex_quote(prompt_text)}; \
echo; echo "Repo path: {repo_dir}"; \
echo "You can now edit files, run tests, install deps, etc."; \
echo "When you are finished, close this terminal to continue the automation..."; \
{os.environ.get('SHELL', '/bin/bash')}"""

    if dry_run and not session_in_dry_run:
        logger.info("[DRY-RUN] Skipping helper session terminal. Use --session-in-dry-run to test it.")
        logger.info("[DRY-RUN] Session command would be:\n%s", cmd)
        return

    sys_os = platform.system().lower()
    try:
        if "darwin" in sys_os and shutil.which("osascript"):
            escaped_cmd = cmd.replace('"', '\\"')
            osa_cmd = f'tell application "Terminal" to do script "{escaped_cmd}"'
            run(["osascript", "-e", osa_cmd], check=False)
            input("Opened a new Terminal window. Press ENTER here after you close it to continue...")
            return
        elif "linux" in sys_os:
            if shutil.which("gnome-terminal"):
                run(["gnome-terminal", "--", "bash", "-lc", cmd], check=False)
                input("Press ENTER here after you close the new terminal to continue...")
                return
            elif shutil.which("x-terminal-emulator"):
                run(["x-terminal-emulator", "-e", "bash", "-lc", cmd], check=False)
                input("Press ENTER here after you close the new terminal to continue...")
                return
    except Exception:
        pass

    logger.warning("No external terminal detected; running session inline.")
    print("----- SESSION START -----")
    subprocess.run(cmd, shell=True, check=False)
    print("----- SESSION END -----")


def shlex_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


# ----------------------------
# PR creation
# ----------------------------
def create_draft_pr(client: GHClient, repo_full: str, base_branch: str, head_branch: str, title: str, body: str, logger: logging.Logger) -> Optional[str]:
    status, js = client.get(f"/repos/{repo_full}", params=None, page=None)
    if status != 200 or not isinstance(js, dict):
        logger.error("Failed to get repo metadata for %s", repo_full)
        return None
    url = f"{client.base_url}/repos/{repo_full}/pulls"
    payload = {
        "title": title,
        "head": head_branch,
        "base": base_branch,
        "body": body,
        "draft": True,
    }
    client._sleep_if_needed()
    r = client.session.post(url, json=payload, timeout=30)
    client.last_call_ts = time.time()
    client._write_raw("/pulls", None, r.content)
    client._log_preview("/pulls", None, r.status_code, r.content)

    if r.ok:
        try:
            data = r.json()
            return data.get("html_url") or data.get("url")
        except Exception:
            return None
    else:
        logger.error("PR creation failed: %s", r.text)
        return None


# ----------------------------
# Main logic
# ----------------------------
def main():
    ap = argparse.ArgumentParser(description="GitHub Security Fix Helper (Python)")
    ap.add_argument("--repo", help="Process only this repo (owner/name)")
    ap.add_argument("--org", default=ORG, help="Organization (default: YouOrgHere)")
    ap.add_argument("--team-prop-key", default=TEAM_PROP_KEY_DEFAULT, help="Repository custom property key (optional)")
    ap.add_argument("--team-prop-value", default=TEAM_PROP_VALUE_DEFAULT, help="Repository custom property value (optional)")
    ap.add_argument("--min-severity", choices=list(SEV_RANK.keys()), default=DEFAULT_MIN_SEVERITY)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--session-in-dry-run", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--api-log-file", help="Append full raw responses to this file")
    args = ap.parse_args()

    # Logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    log = logging.getLogger("main")

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        log.error("GITHUB_TOKEN env var is required.")
        sys.exit(1)

    client = GHClient(token=token, api_log_file=args.api_log_file, logger=logging.getLogger("gh"))
    proc_logger = logging.getLogger("proc")
    log.info("Starting")

    # Resolve repos
    filter_text: Optional[str] = None
    if args.repo:
        if args.repo in BLACKLIST:
            log.error("Repo %s is blacklisted.", args.repo)
            sys.exit(1)
        repos = [args.repo]
        log.info("Single-repo mode: %s", args.repo)
    else:
        if args.team_prop_key and args.team_prop_value:
            log.info("Fetching repositories with props.%s:%s in org %s...", args.team_prop_key, args.team_prop_value, args.org)
            repos = fetch_repos_for_team(client, args.org, args.team_prop_key, args.team_prop_value, log)
            filter_text = f"props.{args.team_prop_key}:{args.team_prop_value}"
        else:
            log.info("No team property filter provided; listing all repositories in org %s…", args.org)
            repos = fetch_repos_in_org(client, args.org, log)

        if not repos:
            log.error("No repositories found for the selected scope.")
            sys.exit(1)
        repos = [r for r in repos if r not in BLACKLIST]
        log.info("Processing %d repositories after blacklist.", len(repos))

    findings: List[Finding] = []

    for repo in repos:
        log.info("Scanning repo: %s", repo)
        collect_dependabot(client, repo, args.min_severity, findings, log)
        collect_codescan(client, repo, args.min_severity, findings, log)

    write_findings_md(findings, args.repo, args.min_severity, FINDINGS_FILE, filter_text)
    log.info("Wrote findings to: %s", FINDINGS_FILE)
    log.info("Alert candidates found so far: %d", len(findings))

    if not findings:
        log.info("No alerts >= %s found — no session to open.", args.min_severity)
        return

    prioritized = prioritize_findings(findings, args.min_severity)
    if not prioritized:
        log.info("No alerts matched prioritization rules — nothing to do.")
        return

    total_candidates = len(prioritized)
    log.info("Prioritized %d alert(s) for guided fixes.", total_candidates)

    for idx, chosen in enumerate(prioritized, start=1):
        log.info(
            "Processing alert %d/%d => Repo: %s | Source: %s | Severity: %s | Ident: %s",
            idx,
            total_candidates,
            chosen.repo,
            chosen.source,
            chosen.severity,
            chosen.identifier or "n/a",
            )

        temp_dir = None
        work_repo = None
        try:
            if args.dry_run:
                log.info("[DRY-RUN] Would clone %s and create a temp security patch branch.", chosen.repo)
                work_repo = "/tmp/repo"
            else:
                temp_dir = tempfile.mkdtemp(prefix="secfix-")
                work_repo = os.path.join(temp_dir, "repo")
                log.info("Working directory: %s", temp_dir)
                log.info("Cloning %s…", chosen.repo)
                git_clone_with_token(chosen.repo, work_repo, token)

                # default branch
                status, meta = client.get(f"/repos/{chosen.repo}", params=None, page=None)
                default_branch = (meta or {}).get("default_branch") or "main"

                # checkout temp branch from default
                run(["git", "fetch", "origin", default_branch], cwd=work_repo, check=False)
                run(["git", "checkout", "-B", "temp-security-patch-branch", f"origin/{default_branch}"], cwd=work_repo, check=False)

            prompt = (
                'Can you help me generate a automated test, it can either be a unit-test or a integration-test, '
                'that checks for this security-problem, then figure out the code involved, generates 3 unit- or '
                'integration- tests that validate the functionality of the code, before trying to fix this security issue '
                f'in this repo? The security-issue is described as this: "{chosen.header}: {chosen.description}". '
                'Then run all tests and check that the code still works as expected. If tests fail, try to fix the code until all tests pass.'
            )
            open_new_terminal_and_wait(prompt, work_repo, args.dry_run, args.session_in_dry_run, log)

            if args.dry_run:
                log.info("[DRY-RUN] Would detect changes, create branch, commit, push, and open a DRAFT PR.")
                continue

            if work_repo and git_has_changes(work_repo):
                log.info("Changes detected; preparing commit & DRAFT PR…")
                ident = chosen.identifier or re.sub(r"[^A-Za-z0-9-]+", "-", chosen.header)[:40] or "update"
                branch = f"sec-fix-{sanitize_branch(ident)}"
                # rename branch to final
                run(["git", "branch", "-M", branch], cwd=work_repo)
                run(["git", "add", "-A"], cwd=work_repo)
                run(["git", "commit", "-m", f"Security fix: {chosen.header} ({chosen.identifier or 'no-id'})"], cwd=work_repo)
                # push
                run(["git", "push", "-u", "origin", branch], cwd=work_repo)

                # need default branch for base
                status, meta = client.get(f"/repos/{chosen.repo}", params=None, page=None)
                default_branch = (meta or {}).get("default_branch") or "main"

                pr_title = f"Security fix: {chosen.header}"
                pr_body = (
                    f"**Severity:** {chosen.severity}\n"
                    f"**Identifier:** {chosen.identifier or 'n/a'}\n\n"
                )
                url = create_draft_pr(client, chosen.repo, default_branch, branch, pr_title, pr_body, log)
                if url:
                    log.info("Draft PR created: %s", url)
                else:
                    log.error("Draft PR creation failed.")
            else:
                log.info("No changes detected; moving to next alert.")

        finally:
            if temp_dir and os.path.isdir(temp_dir):
                log.info("Cleaning up temp dir: %s", temp_dir)
                shutil.rmtree(temp_dir, ignore_errors=True)

    log.info("Finished processing %d alert(s).", total_candidates)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        sys.exit(130)
