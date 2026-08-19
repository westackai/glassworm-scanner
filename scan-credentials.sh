#!/usr/bin/env bash
#
# glassworm/scan-credentials.sh — find exposed secret material in local repos
# and open GitHub organization secret-scanning alerts.
#
# Separate from the GlassWorm scanners on purpose: leaked credentials are their
# own problem with their own remediation (revoke, then rotate), and you want to
# be able to run this on repos that were never worm-infected.
#
# By default this reports only what is EXPOSED IN GIT — i.e. content that has
# been committed and therefore reached (or can reach) the remote. A gitignored
# .env sitting on your own disk is not a leak and is NOT reported unless you
# ask for it with --local.
#
# Scans, per repository under the given roots (default: ~/Projects ~/github):
#   1. TRACKED FILES     — every file git tracks at each local branch tip.
#                          This is what is on the remote.
#   2. GIT HISTORY       — with --history: secrets committed and later deleted.
#                          Still in the repo, still valid, still fetchable.
#   3. .git/config       — credentials embedded in remote URLs (local-only, but
#                          a live credential; shown because it needs revoking)
#   4. LOCAL FILES       — with --local: untracked/gitignored files on disk
#                          (.env, .npmrc). Not leaked, but worth knowing about
#                          if the machine itself may be compromised.
#   5. LOOSE FILES       — with --all-files: files outside git repositories too
#   6. GITHUB ORGS       — with --org: open organization secret-scanning alerts,
#                          requested from GitHub with secret values hidden
#
# READ-ONLY. Local-path scans are offline. --org uses read-only GitHub API GETs,
# and --tsv explicitly creates a new redacted mode-0600 report. Never verifies
# a token against a network service.
#
# SECRETS ARE ALWAYS REDACTED. Raw matches are not stored in temporary files or
# passed to child-process arguments.
#
# Usage:
#   ./scan-credentials.sh [--history] [--local] [--all-files]
#                         [--org OWNER ...] [--tsv NEW_FILE] [ROOT ...]
#
# Options:
#   --history    scan every commit reachable from all local refs (slow)
#   --local      ALSO report untracked/gitignored files on disk (.env etc).
#                Off by default: a gitignored .env is not exposed on the remote.
#   --all-files  scan each complete root once, including non-repository files
#   --org OWNER  list open GitHub secret-scanning alerts for an organization;
#                repeat for multiple organizations; secret values stay hidden
#   --tsv FILE   create a new redacted mode-0600 TSV; refuses overwrite
#
# Exit: 0=no actionable matches, 1=matches, 2=incomplete/fatal.
#
set -uo pipefail
export LC_ALL=C LANG=C
export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/true GIT_OPTIONAL_LOCKS=0
export GIT_SSH_COMMAND=/usr/bin/false
umask 077

case "$-" in
  *x*) echo "refusing to scan secrets while shell xtrace is enabled" >&2; exit 2 ;;
esac

# Caller-provided debug/trace settings can log authenticated HTTP or Git traffic.
# This scanner never needs them and deliberately neutralizes them.
unset GH_DEBUG DEBUG GIT_TRACE GIT_TRACE_CURL GIT_TRACE_PACKET GIT_TRACE_PACKFILE
unset GIT_TRACE2 GIT_TRACE2_EVENT GIT_TRACE2_PERF GIT_TRACE2_BRIEF GIT_TRACE2_CONFIG_PARAMS
export GIT_TRACE_REDACT=1 GIT_NO_REPLACE_OBJECTS=1

HERE="$(cd "$(dirname "$0")" && pwd)"
DB="$HERE/data/credential-patterns.tsv"
IGNORE="$HERE/data/credential-ignore.txt"
GITHUB_HOST="github.com"
GITHUB_API_VERSION="2026-03-10"

# Files whose contents are data, not code. Base64/binary payloads in these
# routinely produce 20-char runs that match AWS/Google key shapes by chance.
BINARY_EXCLUDES=(--exclude='*.svg' --exclude='*.jpg' --exclude='*.jpeg' --exclude='*.png'
  --exclude='*.gif' --exclude='*.webp' --exclude='*.ico' --exclude='*.pdf'
  --exclude='*.woff' --exclude='*.woff2' --exclude='*.ttf' --exclude='*.eot' --exclude='*.otf'
  --exclude='*.min.js' --exclude='*.map' --exclude='*.lock' --exclude='*.wasm')

# Shannon-ish check: real keys are usually high-entropy; repeated/padded test
# strings are not.
# Read the candidate on stdin so it never appears in another process's argv.
low_entropy() { # value -> 0 (true) when it looks like padding/repetition
  printf '%s' "$1" | python3 -c '
import sys,collections,math
v=sys.stdin.read()
body=v.split('_')[-1].split('-')[-1]
if len(body)<8: sys.exit(1)
c=collections.Counter(body)
if max(c.values())/len(body) > 0.45: sys.exit(0)      # one char dominates
h=-sum((n/len(body))*math.log2(n/len(body)) for n in c.values())
sys.exit(0 if h < 2.6 else 1)
' 2>/dev/null
}

is_ignored() { # value
  [ -f "$IGNORE" ] || return 1
  local pat
  while IFS= read -r pat; do
    case "$pat" in ''|\#*) continue ;; esac
    case "$1" in *"$pat"*) return 0 ;; esac
  done < "$IGNORE"
  return 1
}

HISTORY=0; ALL_FILES=0; LOCAL=0; TSV=""; ROOTS=(); ORGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --history) HISTORY=1; shift ;;
    --local)   LOCAL=1; shift ;;
    --all-files) ALL_FILES=1; shift ;;
    --org)
      [ "$#" -ge 2 ] && [ -n "$2" ] || { echo "--org needs an organization login" >&2; exit 2; }
      ORGS+=("$2"); shift 2 ;;
    --tsv)
      [ "$#" -ge 2 ] && [ -n "$2" ] || { echo "--tsv needs a file" >&2; exit 2; }
      TSV="$2"; shift 2 ;;
    --show|--unsafe-show-secrets)
      echo "full-secret output is disabled; use the redacted value/fingerprint to identify and revoke it" >&2
      exit 2 ;;
    -h|--help) sed -n '2,49p' "$0"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) ROOTS+=("$1"); shift ;;
  esac
done
[ ${#ROOTS[@]} -gt 0 ] || [ ${#ORGS[@]} -gt 0 ] || ROOTS=("$HOME/Projects" "$HOME/github")
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
command -v shasum >/dev/null 2>&1 || { echo "shasum is required" >&2; exit 2; }

for org in "${ORGS[@]+"${ORGS[@]}"}"; do
  if [[ ! "$org" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]; then
    echo "invalid GitHub organization login: $org" >&2
    exit 2
  fi
done
if [ ${#ORGS[@]} -gt 0 ]; then
  command -v gh >/dev/null 2>&1 || { echo "gh is required for --org" >&2; exit 2; }
  gh auth status --hostname "$GITHUB_HOST" >/dev/null 2>&1 || {
    echo "gh is not authenticated for $GITHUB_HOST; run gh auth login" >&2
    exit 2
  }
fi
[ -f "$DB" ] || { echo "missing pattern DB: $DB" >&2; exit 2; }
awk -F'\t' '
  /^#/ || /^[[:space:]]*$/ { next }
  NF != 4 || ($2 != "critical" && $2 != "review" && $2 != "public") { bad=1 }
  END { exit bad }
' "$DB" || { echo "malformed credential pattern DB: $DB" >&2; exit 2; }

if [ -n "$TSV" ]; then
  if [ -e "$TSV" ] || [ -L "$TSV" ]; then
    echo "refusing to overwrite report path: $TSV" >&2
    exit 2
  fi
  NOCLOBBER_WAS=0; case "$-" in *C*) NOCLOBBER_WAS=1 ;; esac
  set -o noclobber
  if ! exec 3> "$TSV"; then
    [ "$NOCLOBBER_WAS" -eq 1 ] || set +o noclobber
    echo "cannot securely create new report: $TSV" >&2
    exit 2
  fi
  [ "$NOCLOBBER_WAS" -eq 1 ] || set +o noclobber
  chmod 600 /dev/fd/3 2>/dev/null || { echo "cannot secure report mode: $TSV" >&2; exit 2; }
  printf 'location\twhere\tpath\ttype\tredacted\tfingerprint\n' >&3
fi

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'
else RED=""; GRN=""; YEL=""; CYN=""; DIM=""; BLD=""; RST=""; fi

FINDINGS=0; ACTIONABLE=0; REPOS=0; INVALID_GIT=0; LOOSE_ROOTS=0; CRITICAL_N=0; REVIEW_N=0; PUBLIC_N=0; PARTIAL=0
ORGS_SCANNED=0; ORG_ALERTS=0; ORG_REPOS_VISIBLE=0; ORG_SECRET_ENABLED=0; ORG_SECRET_DISABLED=0; ORG_SECRET_UNKNOWN=0
HITLIST="$(mktemp)"; ORG_ALERTS_TMP="$(mktemp)"; ORG_REPOS_TMP="$(mktemp)"
trap 'rm -f "$HITLIST" "$ORG_ALERTS_TMP" "$ORG_REPOS_TMP" "${SEEN_KEYS:-}"' EXIT

redact() { # value
  case "$1" in
    http://*@*|https://*@*)
      printf '%s' "$1" | sed -E 's#^(https?://)[^@]+(@.*)$#\1[REDACTED]\2#'
      return ;;
  esac
  printf '%s' "$1" | sed -E 's/^(.{6}).*(.{4})$/\1…\2/'
}

fingerprint() { # candidate value; value is supplied on stdin to shasum
  printf '%s' "$1" | shasum -a 256 | awk '{print substr($1,1,12)}'
}

SEEN_KEYS="$(mktemp)"
report() { # repo where path id value
  is_ignored "$5" && return 0
  case "$4" in
    aws-access-key|google-api-key|openai-key-legacy)
      low_entropy "$5" && return 0 ;;
  esac
  local fp key
  fp="$(fingerprint "$5")"
  # Store only metadata + a one-way fingerprint, never the matched credential.
  key="$1|$2|$3|$4|$fp"
  grep -qxF "$key" "$SEEN_KEYS" 2>/dev/null && return 0
  printf '%s\n' "$key" >> "$SEEN_KEYS"
  FINDINGS=$((FINDINGS+1))
  local v; v="$(redact "$5")"
  local sev tag col
  sev="$(awk -F'\t' -v i="$4" '$1==i{print $2; exit}' "$DB")"
  case "$sev" in
    critical)
      tag="SECRET"; col="$RED"; CRITICAL_N=$((CRITICAL_N+1)); ACTIONABLE=$((ACTIONABLE+1)) ;;
    review)
      tag="REVIEW"; col="$YEL"; REVIEW_N=$((REVIEW_N+1)); ACTIONABLE=$((ACTIONABLE+1)) ;;
    public)
      tag="INFO  "; col="$DIM"; PUBLIC_N=$((PUBLIC_N+1)) ;;
    *)
      tag="REVIEW"; col="$YEL"; REVIEW_N=$((REVIEW_N+1)); ACTIONABLE=$((ACTIONABLE+1)) ;;
  esac
  printf "  ${col}%-8s${RST} ${CYN}%-17s${RST} %-42s ${YEL}%s${RST}  %s  sha256:%s\n" \
    "$tag" "$2" "$3" "$4" "$v" "$fp"
  [ -n "$TSV" ] && printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$v" "$fp" >&3
  [ "$sev" = "public" ] || echo "$1" >> "$HITLIST"
}

sanitize_alert_stream() {
  python3 -c '
import sys, unicodedata
for raw in sys.stdin.buffer:
    value = raw.decode("utf-8", "replace").rstrip("\r\n")
    value = "".join("?" if (unicodedata.category(c) in ("Cc", "Cf") and c not in ("\t", "\x1f")) else c for c in value)
    print(value[:4000])
'
}

valid_repo_full_name() { # owner/repository returned by GitHub
  local full="$1" owner name
  case "$full" in */*/*|/*|*/|'') return 1 ;; esac
  owner="${full%%/*}"; name="${full#*/}"
  [[ "$owner" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]] || return 1
  [[ "$name" =~ ^[A-Za-z0-9._-]{1,100}$ ]] || return 1
  [ "$name" != "." ] && [ "$name" != ".." ]
}

report_org_alert() { # org number repo secret-type display validity created
  local org="$1" number="$2" repo="$3" secret_type="$4" display="$5" validity="$6" created="$7"
  local path="${repo}#secret-scanning-alert-${number}"
  local url="https://${GITHUB_HOST}/${repo}/security/secret-scanning/${number}"
  FINDINGS=$((FINDINGS+1))
  ACTIONABLE=$((ACTIONABLE+1))
  CRITICAL_N=$((CRITICAL_N+1))
  ORG_ALERTS=$((ORG_ALERTS+1))
  printf "  ${RED}%-8s${RST} ${CYN}%-17s${RST} %-42s ${YEL}%s${RST}  validity=%s created=%s  %s\n" \
    "SECRET" "github-alert" "$path" "${display:-$secret_type}" "${validity:-unknown}" "${created:-unknown}" "$url"
  if [ -n "$TSV" ]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "github:$org" "github-alert" "$url" "$secret_type" '[withheld-by-GitHub]' "alert:$number" >&3
  fi
  echo "github:$repo" >> "$HITLIST"
}

scan_org_alerts() { # organization login
  local org="$1" number repo secret_type display validity created
  local status visibility org_visible=0 org_enabled=0 org_disabled=0 org_unknown=0
  : > "$ORG_REPOS_TMP"
  : > "$ORG_ALERTS_TMP"

  printf "${DIM}[github org] %s: checking visible-repository Secret Protection coverage${RST}\n" "$org" >&2
  if ! gh api --hostname "$GITHUB_HOST" --method GET \
      -H 'Accept: application/vnd.github+json' \
      -H "X-GitHub-Api-Version: $GITHUB_API_VERSION" \
      --paginate "/orgs/$org/repos?type=all&per_page=100" \
      --jq '.[] | [(.full_name//""),(.security_and_analysis.secret_scanning.status//"unknown"),(.visibility//"unknown")] | join("\u001f")' \
      2>/dev/null | sanitize_alert_stream > "$ORG_REPOS_TMP"; then
    echo "${YEL}WARN${RST} could not enumerate visible repositories or Secret Protection status for GitHub organization $org" >&2
    PARTIAL=1
  else
    while IFS=$'\x1f' read -r repo status visibility; do
      [ -n "$repo" ] || continue
      if ! valid_repo_full_name "$repo"; then
        echo "${YEL}WARN${RST} malformed repository metadata returned for GitHub organization $org; row skipped" >&2
        PARTIAL=1
        continue
      fi
      org_visible=$((org_visible+1))
      case "$status" in
        enabled) org_enabled=$((org_enabled+1)) ;;
        disabled) org_disabled=$((org_disabled+1)) ;;
        *) org_unknown=$((org_unknown+1)) ;;
      esac
    done < "$ORG_REPOS_TMP"
    ORG_REPOS_VISIBLE=$((ORG_REPOS_VISIBLE+org_visible))
    ORG_SECRET_ENABLED=$((ORG_SECRET_ENABLED+org_enabled))
    ORG_SECRET_DISABLED=$((ORG_SECRET_DISABLED+org_disabled))
    ORG_SECRET_UNKNOWN=$((ORG_SECRET_UNKNOWN+org_unknown))
    printf "${CYN}COVERAGE${RST} GitHub organization %s: visible=%d secret-scanning-enabled=%d disabled=%d unknown=%d\n" \
      "$org" "$org_visible" "$org_enabled" "$org_disabled" "$org_unknown"
    if [ "$org_disabled" -gt 0 ] || [ "$org_unknown" -gt 0 ]; then
      echo "${YEL}WARN${RST} GitHub alert coverage is incomplete for $org; zero alerts cannot establish that the organization is clean" >&2
      PARTIAL=1
    fi
  fi

  printf "${DIM}[github org] %s: querying open secret-scanning alerts for eligible repositories (secret hidden)${RST}\n" "$org" >&2
  if ! gh api --hostname "$GITHUB_HOST" --method GET \
      -H 'Accept: application/vnd.github+json' \
      -H "X-GitHub-Api-Version: $GITHUB_API_VERSION" \
      --paginate "/orgs/$org/secret-scanning/alerts?state=open&hide_secret=true&per_page=100" \
      --jq '.[] | [(.number|tostring),(.repository.full_name//""),(.secret_type//""),(.secret_type_display_name//""),(.validity//""),(.created_at//"")] | join("\u001f")' \
      2>/dev/null | sanitize_alert_stream > "$ORG_ALERTS_TMP"; then
    echo "${YEL}WARN${RST} could not read open secret-scanning alerts for GitHub organization $org" >&2
    echo "     Verify organization access and the Secret scanning alerts read permission." >&2
    PARTIAL=1
    return 0
  fi

  ORGS_SCANNED=$((ORGS_SCANNED+1))
  if [ ! -s "$ORG_ALERTS_TMP" ]; then
    printf "${GRN}INFO${RST} GitHub organization %s returned no open secret-scanning alerts for eligible repositories\n" "$org"
    return 0
  fi

  while IFS=$'\x1f' read -r number repo secret_type display validity created; do
    if [[ ! "$number" =~ ^[0-9]+$ ]] || ! valid_repo_full_name "$repo" || [ -z "$secret_type" ]; then
      echo "${YEL}WARN${RST} malformed alert metadata returned for GitHub organization $org; row skipped" >&2
      PARTIAL=1
      continue
    fi
    report_org_alert "$org" "$number" "$repo" "$secret_type" "$display" "$validity" "$created"
  done < "$ORG_ALERTS_TMP"
}

# 1. TRACKED files — what is actually committed, i.e. what is on the remote.
#    Uses git grep across every local branch tip, so a secret committed on a
#    branch you are not currently standing on is still found.
scan_tracked() { # gitdir label
  local gd="$1" label="$2" id sev re desc hit path val tips grep_rc
  if ! tips="$(git --git-dir="$gd" for-each-ref refs/heads --format='%(objectname)' 2>/dev/null | sort -u)"; then
    echo "${YEL}WARN${RST} could not enumerate local branch tips for $label" >&2
    PARTIAL=1
    return 0
  fi
  [ -n "$tips" ] || return 0
  while IFS=$'\t' read -r id sev re desc; do
    case "$id" in ''|\#*) continue ;; esac
    while IFS= read -r hit; do
      [ -n "$hit" ] || continue
      if [ "$hit" = "__CREDENTIAL_SCAN_INCOMPLETE__" ]; then
        echo "${YEL}WARN${RST} tracked-content scan failed for $label ($id)" >&2
        PARTIAL=1
        continue
      fi
      path="${hit#*:}"; path="${path%%:*}"
      val="$(printf '%s' "$hit" | grep -oE "$re" | head -1)"
      [ -n "$val" ] && report "$label" "tracked" "$path" "$id" "$val"
    done < <(
      git --git-dir="$gd" grep -I -E -o -e "$re" $tips -- \
        ':(exclude,glob)**/*.svg' ':(exclude,glob)**/*.jpg' ':(exclude,glob)**/*.jpeg' \
        ':(exclude,glob)**/*.png'  ':(exclude,glob)**/*.map' ':(exclude,glob)**/*.min.js' \
        ':(exclude,glob)**/node_modules/**' 2>/dev/null
      grep_rc=$?
      [ "$grep_rc" -le 1 ] || printf '%s\n' '__CREDENTIAL_SCAN_INCOMPLETE__'
    )
  done < "$DB"
}

# 4. --local: untracked / gitignored files on disk. NOT a leak; shown only when
#    asked, because a compromised machine can still have them read.
scan_tree() { # dir label [worktree]
  local dir="$1" label="$2" id sev re desc line file val grep_rc
  while IFS=$'\t' read -r id sev re desc; do
    case "$id" in ''|\#*) continue ;; esac
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      if [ "$line" = "__CREDENTIAL_SCAN_INCOMPLETE__" ]; then
        echo "${YEL}WARN${RST} local-file scan failed for $label ($id)" >&2
        PARTIAL=1
        continue
      fi
      file="${line%%:*}"; val="${line#*:}"
      report "$label" "local-only" "${file#"$dir"/}" "$id" "$val"
    done < <(
      grep -rIoE "$re" "$dir" \
        --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv \
        --exclude-dir=venv --exclude-dir=dist --exclude-dir=build --exclude-dir=.next \
        "${BINARY_EXCLUDES[@]}" --exclude='credential-*.tsv' --exclude='credential-ignore.txt' \
        2>/dev/null
      grep_rc=$?
      [ "$grep_rc" -le 1 ] || printf '%s\n' '__CREDENTIAL_SCAN_INCOMPLETE__'
    )
  done < "$DB"
}

# 2. credentials baked into git remote URLs
scan_remotes() { # gitdir label
  local gd="$1" label="$2" hit
  [ -f "$gd/config" ] || return 0
  while IFS= read -r hit; do
    [ -n "$hit" ] && report "$label" "git-remote" ".git/config" "git-url-creds" "$hit"
  done < <(grep -Eo \
    'https://([^/@:[:space:]]+:[^/@[:space:]]{8,}|(gh[pousr]_|github_pat_)[A-Za-z0-9._-]{20,})@[A-Za-z0-9_.-]+' \
    "$gd/config" 2>/dev/null)
}

# 4. secrets that were committed at any point (still recoverable, still valid)
scan_history() { # gitdir label
  local gd="$1" label="$2" id path val

  # Stream each reachable commit diff once. --root catches values introduced in
  # the first commit; -m catches merge-resolution additions. Raw matches travel
  # only through this pipe into report(), never through argv or a temporary file.
  while IFS=$'\t' read -r id path val; do
    if [ "$id" = "__INCOMPLETE__" ]; then
      echo "${YEL}WARN${RST} history scan failed for $label" >&2
      PARTIAL=1
      continue
    fi
    [ -n "$id" ] && [ -n "$val" ] && report "$label" "history" "$path" "$id" "$val"
  done < <(python3 - "$DB" "$gd" <<'PY'
import re, subprocess, sys

db_path, git_dir = sys.argv[1:3]
patterns = []
try:
    with open(db_path, "r", encoding="utf-8") as source:
        for raw in source:
            if not raw.strip() or raw.startswith("#"):
                continue
            ident, _severity, expression, _description = raw.rstrip("\n").split("\t", 3)
            # Translate the one POSIX character class used by the ERE database.
            expression = expression.replace("[[:space:]]", r"\s")
            patterns.append((ident.encode(), re.compile(expression.encode())))
except (OSError, ValueError, re.error):
    sys.stdout.buffer.write(b"__INCOMPLETE__\tpattern-db\tfailed\n")
    sys.exit(0)

command = [
    "git", "--git-dir=" + git_dir, "-c", "core.quotePath=false",
    "log", "--all", "--root", "-m", "-p", "--no-renames",
    "--no-ext-diff", "--no-textconv", "--format=",
]
try:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
except OSError:
    sys.stdout.buffer.write(b"__INCOMPLETE__\tgit-log\tfailed\n")
    sys.exit(0)

old_path = b"unknown"
path = b"unknown"
for line in process.stdout:
    if line.startswith(b"--- "):
        old_path = line[4:].rstrip(b"\r\n")
        if old_path.startswith(b"a/"):
            old_path = old_path[2:]
        continue
    if line.startswith(b"+++ "):
        candidate = line[4:].rstrip(b"\r\n")
        if candidate == b"/dev/null":
            path = old_path
        else:
            path = candidate[2:] if candidate.startswith(b"b/") else candidate
        continue
    if not line.startswith((b"+", b"-")):
        continue
    content = line[1:].rstrip(b"\r\n")
    safe_path = path.replace(b"\t", b"?").replace(b"\r", b"?").replace(b"\n", b"?")
    for ident, expression in patterns:
        for match in expression.finditer(content):
            sys.stdout.buffer.write(ident + b"\t" + safe_path + b"\t" + match.group(0) + b"\n")

if process.wait() != 0:
    sys.stdout.buffer.write(b"__INCOMPLETE__\tgit-log\tfailed\n")
PY
  )
}

echo "${BLD}Exposed-credential scan${RST}"
if [ ${#ROOTS[@]} -gt 0 ]; then echo "Local roots: ${ROOTS[*]}"; else echo "Local roots: none"; fi
if [ ${#ORGS[@]} -gt 0 ]; then echo "GitHub organizations: ${ORGS[*]} (open secret-scanning alerts, values hidden)"; fi
SCOPE=""
if [ ${#ROOTS[@]} -gt 0 ]; then
  SCOPE="local committed content$([ "$HISTORY" = 1 ] && echo ' + full local git history' || echo ' at local branch tips')$([ "$LOCAL" = 1 ] && echo ' + local untracked files' || echo '')"
fi
if [ ${#ORGS[@]} -gt 0 ]; then SCOPE="${SCOPE:+$SCOPE + }GitHub-managed org alert coverage"; fi
echo "Scope: $SCOPE"
echo "Values: local matches are redacted and fingerprinted; GitHub alert secrets are withheld server-side"
echo "Started: $(date)"
echo

for org in "${ORGS[@]+"${ORGS[@]}"}"; do
  scan_org_alerts "$org"
done
if [ ${#ORGS[@]} -gt 0 ]; then
  echo "${DIM}GitHub organization mode uses GitHub Secret Protection alerts; local pattern and --history scanning still require local repository paths.${RST}"
  echo
fi

VALID_ROOTS=()
for root in "${ROOTS[@]+"${ROOTS[@]}"}"; do
  if [ -d "$root" ]; then
    VALID_ROOTS+=("$root")
  else
    echo "${YEL}WARN${RST} missing/unreadable root: $root" >&2
    case "$root" in
      */*) ;;
      *) echo "     To scan a GitHub organization, use: $0 --org $root" >&2 ;;
    esac
    PARTIAL=1
  fi
done
ROOTS=()
if [ ${#VALID_ROOTS[@]} -gt 0 ]; then ROOTS=("${VALID_ROOTS[@]}"); fi

if [ ${#ROOTS[@]} -eq 0 ] && [ ${#ORGS[@]} -eq 0 ]; then
  echo "no readable scan roots" >&2
  exit 2
fi

if [ "$ALL_FILES" = 1 ]; then
  for root in "${ROOTS[@]+"${ROOTS[@]}"}"; do
    LOOSE_ROOTS=$((LOOSE_ROOTS+1))
    label="${root/#$HOME/\~}"
    printf "${DIM}[root %d] %s${RST}\n" "$LOOSE_ROOTS" "$label" >&2
    scan_tree "$root" "$label"
  done
fi

if [ ${#ROOTS[@]} -gt 0 ]; then
  while IFS= read -r gitpath; do
    wt="$(dirname "$gitpath")"
    gd="$gitpath"
    [ -f "$gitpath" ] && gd="$(sed -n 's/^gitdir: //p' "$gitpath" | head -1)"
    case "$gd" in /*) ;; *) gd="$wt/$gd" ;; esac
    [ -d "$gd" ] || continue
    label="${wt/#$HOME/\~}"
    if ! git --git-dir="$gd" rev-parse --git-dir >/dev/null 2>&1; then
      INVALID_GIT=$((INVALID_GIT+1))
      echo "${YEL}WARN${RST} invalid/incomplete Git metadata at $label; scanning files only" >&2
      [ "$ALL_FILES" = 1 ] || scan_tree "$wt" "$label"
      if [ "$HISTORY" = 1 ]; then
        echo "${YEL}WARN${RST} history is unavailable for $label" >&2
        PARTIAL=1
      fi
      continue
    fi
    REPOS=$((REPOS+1))
    printf "${DIM}[%d] %s${RST}\n" "$REPOS" "$label" >&2
    scan_tracked "$gd" "$label"
    # untracked/gitignored files are NOT exposed on the remote; opt in with --local
    if [ "$LOCAL" = 1 ] && [ "$ALL_FILES" = 0 ]; then scan_tree "$wt" "$label" "$wt"; fi
    scan_remotes "$gd" "$label"
    [ "$HISTORY" = 1 ] && scan_history "$gd" "$label"
  done < <(find "${ROOTS[@]}" \( -name node_modules -o -name .venv -o -name venv \) -prune -o \
             -name .git \( -type d -o -type f \) -print -prune 2>/dev/null)
fi

if [ ${#ROOTS[@]} -gt 0 ] && [ "$REPOS" -eq 0 ] && [ "$ALL_FILES" -eq 0 ]; then
  echo "${YEL}WARN${RST} no git repositories discovered; no file contents were scanned" >&2
  PARTIAL=1
fi

echo
echo "${BLD}=== Summary ===${RST}"
echo "Local repos: $REPOS   Invalid Git dirs: $INVALID_GIT   Whole roots: $LOOSE_ROOTS"
echo "GitHub orgs queried: $ORGS_SCANNED   Open GitHub alerts: $ORG_ALERTS"
echo "Visible GitHub repos: $ORG_REPOS_VISIBLE   Secret scanning enabled: $ORG_SECRET_ENABLED   Disabled: $ORG_SECRET_DISABLED   Unknown: $ORG_SECRET_UNKNOWN"
echo "Secrets: ${CRITICAL_N}   Review: ${REVIEW_N}   Informational: ${PUBLIC_N}"
if [ -s "$HITLIST" ]; then
  echo "${RED}${BLD}Locations requiring action ($(sort -u "$HITLIST" | wc -l | tr -d ' ')):${RST}"
  sort -u "$HITLIST" | sed 's/^/  /'
  echo
  echo "${YEL}If active abuse is suspected, revoke immediately. Otherwise create a replacement,${RST}"
  echo "${YEL}update and verify every consumer, then revoke the old credential.${RST}"
  echo "Deleting a file or rewriting git history does not revoke a credential."
else
  if [ "$PARTIAL" -ne 0 ]; then
    echo "${YEL}${BLD}No actionable matches were returned from the completed portions, but coverage is incomplete.${RST}"
  else
    echo "${GRN}${BLD}No actionable token-shaped material or open GitHub secret-scanning alerts found in the scanned coverage.${RST}"
  fi
  if [ ${#ROOTS[@]} -gt 0 ]; then
    [ "$HISTORY" = 0 ] && echo "${DIM}(local branch tips only — add --history for secrets committed then deleted)${RST}"
    [ "$LOCAL" = 0 ] && echo "${DIM}(local committed content only — add --local to also list untracked .env files on disk)${RST}"
  fi
fi
[ -n "$TSV" ] && echo "Redacted TSV report: $TSV"
echo "Finished: $(date)"
if [ "$PARTIAL" -ne 0 ]; then
  echo "${YEL}RESULT INCOMPLETE — review warnings above.${RST}"
  exit 2
fi
[ "$ACTIONABLE" -eq 0 ]
