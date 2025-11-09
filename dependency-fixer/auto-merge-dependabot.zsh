#!/usr/bin/env zsh

# This script has saved me so much time...

# 1) Install and authenticate
# brew install gh jq
# gh auth login   # or export GH_TOKEN=... with appropriate scopes
#
# 2) Save script
# chmod +x auto-approve-merge-dependabot.sh
#
# 3) Run (real mode)
# ./auto-approve-merge-dependabot.sh
#
# (Optional) Dry run first
# DRY_RUN=true ./auto-approve-merge-dependabot.sh
#
# (Optional) Pick a different merge strategy
# MERGE_METHOD=squash ./auto-approve-merge-dependabot.sh
#
# (Optional) Custom property filtering:
#   PROPERTY_KEY=team PROPERTY_VALUE=Platform ./auto-approve-merge-dependabot.sh   # key=value
#   PROPERTY_KEY=team ./auto-approve-merge-dependabot.sh                           # has key (any value)
#   (unset both) -> no filtering, process all repos

set -euo pipefail
unsetopt xtrace 2>/dev/null || true

export GH_NO_TTY=1
export GH_PAGER=
export PAGER=

# --- Configuration ---
ORG="${ORG:-YourOrgNameHere}"          # GitHub org name
PROPERTY_KEY="${PROPERTY_KEY:-}"       # e.g. team, product, language
PROPERTY_VALUE="${PROPERTY_VALUE:-}"   # e.g. Platform
MERGE_METHOD="${MERGE_METHOD:-merge}"  # merge | squash | rebase
DRY_RUN="${DRY_RUN:-false}"

MODE="${MODE:-rebase}"                       # rebase | recreate
REBASE_IF_BEHIND="${REBASE_IF_BEHIND:-true}" # auto refresh if behind

typeset -a BLACKLIST_REPOS=(
  "some-repo-you-dont-want-to-process"
  "another-repo-to-skip"
)
typeset -a BLACKLIST_PATTERNS=(
  "test-repo-*"
  "demo-*"
)

is_blacklisted() {
  local repo="$1"
  for r in "${BLACKLIST_REPOS[@]}"; do [[ "$repo" == "$r" ]] && return 0; done
  for p in "${BLACKLIST_PATTERNS[@]}"; do case "$repo" in $p) return 0 ;; esac; done
  return 1
}

# ---------- Helpers ----------
is_blank() { local s="${1:-}"; [[ -z "${s//[$' \t\r\n']}" ]]; }

compare_behind_by() {
  local repo="$1" base_branch="$2" head_branch="$3"
  local behind
  behind="$(
    gh api -H "Accept: application/vnd.github+json" \
      "/repos/${repo}/compare/${base_branch}...${head_branch}" \
      --jq '.behind_by // -1' 2>/dev/null || echo ""
  )"
  [[ -z "$behind" ]] && echo -1 || echo "$behind"
}

extract_dep_from_title() {
  local title="$1"
  typeset -g DEP_NAME="" DEP_FROM="" DEP_TO=""
  local core="${title%% in /*}"
  local parsed
  parsed="$(printf '%s' "$core" | perl -ne '
    if (m/^Bump\s+(.+?)\s+from\s+([0-9A-Za-z.\-_+]+)\s+to\s+([0-9A-Za-z.\-_+]+)\b/i) {
      print "$1\t$2\t$3\n";
    }
  ')"
  if [[ -n "$parsed" ]]; then
    DEP_NAME="${parsed%%$'\t'*}"
    local rest="${parsed#*$'\t'}"
    DEP_FROM="${rest%%$'\t'*}"
    DEP_TO="${rest#*$'\t'}"
  fi
}

has_newer_dependabot_pr() {
  local repo="$1" current_pr="$2" dep_name="$3" dep_to="$4"
  [[ -z "$dep_name" || -z "$dep_to" ]] && return 1
  local titles
  titles="$(gh pr list -R "$repo" \
            --search 'author:app/dependabot is:open' \
            --json number,title \
            --jq '.[] | select(.number != '"$current_pr"') | [.number,.title] | @tsv' 2>/dev/null || true)"
  if is_blank "$titles"; then
    titles="$(gh pr list -R "$repo" \
              --author 'dependabot[bot]' --state open \
              --json number,title \
              --jq '.[] | select(.number != '"$current_pr"') | [.number,.title] | @tsv' 2>/dev/null || true)"
  fi
  [[ -z "$titles" ]] && return 1
  local newer_found="false"
  while IFS=$'\t' read -r other_num other_title; do
    [[ -z "${other_num:-}" || -z "${other_title:-}" ]] && continue
    extract_dep_from_title "$other_title"
    [[ -z "$DEP_NAME" || -z "$DEP_TO" ]] && continue
    if [[ "$DEP_NAME" == "$dep_name" ]]; then
      local highest="$(printf '%s\n%s\n' "$dep_to" "$DEP_TO" | sort -V | tail -1)"
      if [[ "$highest" == "$DEP_TO" && "$DEP_TO" != "$dep_to" ]]; then
        info "    Found newer Dependabot PR #$other_num for '$dep_name' → $DEP_TO (current PR targets $dep_to)."
        newer_found="true"; break
      fi
    fi
  done <<< "$titles"
  [[ "$newer_found" == "true" ]]
}

jq_check() { command -v jq >/dev/null 2>&1 || { echo "Please install jq."; exit 1; } }
gh_check() { command -v gh >/dev/null 2>&1 || { echo "Please install gh (GitHub CLI)."; exit 1; } }
jq_check; gh_check

info()  { print -P "%F{cyan}[info]%f $*"; }
warn()  { print -P "%F{yellow}[warn]%f $*"; }
error() { print -P "%F{red}[err ]%f $*"; }
run()   { [[ "$DRY_RUN" == "true" ]] && echo "DRYRUN: $*" || eval "$*"; }

# --- 1) Fetch repos + properties ---
page=1
typeset -a repos_json
repos_json=()

info "Fetching repositories and custom property values for org '$ORG'..."
while :; do
  local resp
  resp="$(gh api -H "Accept: application/vnd.github+json" \
          "/orgs/${ORG}/properties/values?per_page=100&page=${page}" 2>/dev/null || true)"
  if echo "$resp" | jq -e 'type=="object" and .status=="403" and (.message|test("rate limit exceeded"; "i"))' >/dev/null 2>&1; then
    msg="$(echo "$resp" | jq -r '.message // "API rate limit exceeded"')"
    error "GitHub API rate limit hit. $msg"
    warn  "Try again later or use a GH token with higher limits."
    exit 1
  fi
  [[ -z "$resp" || "$resp" = "[]" ]] && break
  repos_json+=("$resp"); (( page++ ))
done

if [[ ${#repos_json[@]} -eq 0 ]]; then
  warn "No repositories returned for org '$ORG' (or insufficient permissions)."
  exit 0
fi

all_repos="$(printf '%s\n' "${repos_json[@]}" | jq -s 'flatten')"

# --- Optional filtering modes ---
# 1) key + value  -> exact match
# 2) key only     -> repos having that property (any value)
# 3) neither / value-only -> no filtering (all repos)
filter_mode=""
if ! is_blank "$PROPERTY_KEY" && ! is_blank "$PROPERTY_VALUE"; then
  filter_mode="key=value"
  target_repos="$(
    echo "$all_repos" | jq \
      --arg key "$PROPERTY_KEY" \
      --arg val "$PROPERTY_VALUE" \
      '[
        .[]
        | select(.properties[]? | select(.property_name == $key and (.value|tostring) == $val))
        | .repository_full_name
      ] | unique'
  )"
elif ! is_blank "$PROPERTY_KEY" && is_blank "$PROPERTY_VALUE"; then
  filter_mode="has-key"
  target_repos="$(
    echo "$all_repos" | jq \
      --arg key "$PROPERTY_KEY" \
      '[
        .[]
        | select(.properties[]? | select(.property_name == $key))
        | .repository_full_name
      ] | unique'
  )"
else
  [[ -n "$PROPERTY_VALUE" && -z "$PROPERTY_KEY" ]] && warn "PROPERTY_VALUE provided without PROPERTY_KEY → ignoring value; no filtering."
  filter_mode="none"
  target_repos="$(
    echo "$all_repos" | jq '[ .[] | .repository_full_name ] | unique'
  )"
fi

count="$(echo "$target_repos" | jq 'length')"
case "$filter_mode" in
  "key=value") info "Found $count repositories with $PROPERTY_KEY:$PROPERTY_VALUE." ;;
  "has-key")   info "Found $count repositories that define property '$PROPERTY_KEY' (any value)." ;;
  "none")      info "Found $count repositories (no property filter)." ;;
esac

if [[ "$count" -eq 0 ]]; then
  warn "No repositories matched the selected filtering mode."
  exit 0
fi

# --- 2) Process Dependabot PRs per repo ---
echo "$target_repos" | jq -r '.[]' | while read -r FULLNAME; do
  if is_blacklisted "$FULLNAME"; then
    info "Skipping $FULLNAME (blacklisted)."; continue
  fi
  info "Processing repo: $FULLNAME"

  prs="$(gh pr list -R "$FULLNAME" \
        --search 'author:app/dependabot is:open' \
        --json number,title,url,author,baseRefName,headRefName \
        --jq '.[] | [.number, .title, .url, .author.login, .baseRefName, .headRefName] | @tsv' 2>/dev/null || true)"
  if is_blank "$prs"; then
    prs="$(gh pr list -R "$FULLNAME" \
          --author 'dependabot[bot]' --state open \
          --json number,title,url,author,baseRefName,headRefName \
          --jq '.[] | [.number, .title, .url, .author.login, .baseRefName, .headRefName] | @tsv' 2>/dev/null || true)"
  fi
  if is_blank "$prs"; then
    info "  No open Dependabot PRs."; continue
  fi

  printf '%s\n' "$prs" | awk 'NF' | while IFS=$'\t' read -r PR_NUMBER PR_TITLE PR_URL PR_AUTHOR BASE_REF HEAD_REF; do
    : ${PR_NUMBER:=} ${PR_TITLE:=} ${PR_URL:=} ${PR_AUTHOR:=} ${BASE_REF:=} ${HEAD_REF:=}
    [[ -z "$PR_NUMBER$PR_TITLE$PR_URL" ]] && continue

    info "  PR #${PR_NUMBER} by ${PR_AUTHOR}: ${PR_TITLE}"
    [[ -z "$BASE_REF" ]] && BASE_REF="main"

    extract_dep_from_title "${PR_TITLE}"
    if [[ -n "$DEP_NAME" && -n "$DEP_TO" ]]; then
      if has_newer_dependabot_pr "$FULLNAME" "$PR_NUMBER" "$DEP_NAME" "$DEP_TO"; then
        info "    Skipping: newer PR for '${DEP_NAME}' already open."; continue
      fi
    fi

    if [[ "$REBASE_IF_BEHIND" == "true" ]]; then
      behind_by="$(compare_behind_by "$FULLNAME" "$BASE_REF" "$HEAD_REF")"
      if [[ "$behind_by" -gt 0 ]]; then
        info "    Behind '$BASE_REF' by $behind_by commit(s). Requesting @dependabot $MODE…"
        if [[ "$DRY_RUN" == "true" ]]; then
          echo "DRYRUN: gh pr comment -R \"$FULLNAME\" \"$PR_NUMBER\" --body \"@dependabot $MODE\""
        else
          gh pr comment -R "$FULLNAME" "$PR_NUMBER" --body "@dependabot $MODE" >/dev/null 2>&1 || \
            warn "    Failed to post refresh comment."
        fi
        info "    Skipping checks/merge this run."; continue
      elif [[ "$behind_by" -eq -1 ]]; then
        warn "    Could not determine compare status; continuing."
      else
        info "    Branch is up to date with '$BASE_REF'."
      fi
    fi

    pass_expr='length > 0 and (all(.[]; .bucket == "pass" or .bucket == "success" or .bucket == "neutral" or .bucket == "skipped"))'
    : ${GH_NO_TTY:=1}; export GH_NO_TTY GH_PAGER
    passed="$(gh pr checks -R "$FULLNAME" "$PR_NUMBER" --json bucket --jq "$pass_expr" 2>/dev/null || echo "")"
    if [[ -z "$passed" ]]; then info "    Could not evaluate checks. Skipping."; continue; fi
    if [[ "$passed" != "true" ]]; then info "    Checks not all passing yet. Skipping."; continue; fi
    info "    Checks: PASSED ✅"

    if [[ "$DRY_RUN" == "true" ]]; then
      echo "DRYRUN: gh pr review -R \"$FULLNAME\" \"$PR_NUMBER\" --approve"
      echo "DRYRUN: gh pr merge  -R \"$FULLNAME\" \"$PR_NUMBER\" --${MERGE_METHOD} --delete-branch --auto=false"
    else
      gh pr review -R "$FULLNAME" "$PR_NUMBER" --approve >/dev/null 2>&1 || true
      if gh pr merge -R "$FULLNAME" "$PR_NUMBER" --${MERGE_METHOD} --delete-branch --auto=false; then
        info "    Merged 🎉"
      else
        warn "    Merge returned non-zero (queue/protection?)."
      fi
    fi
  done

  info "Done."
done
