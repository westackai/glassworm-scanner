#!/usr/bin/env bash
#
# glassworm-scan6.sh — API-only Glassworm scanner/remediator for GitHub.
#
# No repository is cloned or checked out locally. The script uses `gh api` to:
#   * enumerate every branch and tree on GitHub
#   * fetch only candidate blobs for inspection
#   * find the newest clean historical version of an infected file on that branch
#   * optionally update/delete the infected file directly on GitHub
#
# Modes:
#   (no mode)          scan only; never changes GitHub
#   --dry-run-github   scan + show the exact GitHub remediation plan; no writes
#   --clean-github     scan + apply safe remediation commits directly to GitHub
#
# Safe-remediation rules:
#   * config/tasks files: restore only from a verified clean historical version
#   * known helper artifacts: delete directly
#   * fake text/ASCII fonts: restore a clean binary version, otherwise delete
#   * .gitignore: restore clean history; if none, remove only known helper entries
#   * if a config/tasks file has no clean history, leave it unchanged for manual review
#
# Usage:
#   ./scan-github.sh [OWNER | OWNER/REPO ...] [options]
#
# Targets:
#   OWNER            scan every repo of that org/user   (e.g. westackai)
#   OWNER/REPO       scan just that one repo            (e.g. courtpass/kiosk-app)
#   (no target)      scan your account + every org you belong to
#
# Options:
#   --repos-from F       read additional targets (one per line) from file F
#   --include-archived   include archived repositories (default: skip)
#   --include-forks      include fork repositories (default: skip)
#   --dry-run-github     preview direct GitHub cleanup; make no changes
#   --clean-github       commit safe cleanup directly to each infected branch
#   -h, --help           show this help
#
set -uo pipefail
export LC_ALL=C LANG=C GIT_TERMINAL_PROMPT=0
shopt -s nocasematch

OWNERS=()
INCLUDE_ARCHIVED=0
INCLUDE_FORKS=0
MODE="scan"

usage() {
  cat <<'EOF'
scan-github.sh — API-only GlassWorm scanner/remediator for GitHub.

Usage:
  ./scan-github.sh [OWNER | OWNER/REPO ...] [options]

Targets:
  OWNER            scan every repo of that org/user   (e.g. westackai)
  OWNER/REPO       scan just that one repo            (e.g. courtpass/kiosk-app)
  (none)           scan your account + every org you belong to

Modes/options:
  --repos-from F       read additional targets (one per line) from file F
  --include-archived   include archived repositories (default: skip)
  --include-forks      include fork repositories (default: skip)
  --dry-run-github     scan + preview direct GitHub cleanup; make no changes
  --clean-github       scan + commit safe cleanup directly to infected branches
  -h, --help           show this help

Scanning is READ-ONLY. Nothing is written unless you pass --clean-github.
No repository is cloned or checked out locally.

Examples:
  ./scan-github.sh westackai                       # whole org
  ./scan-github.sh courtpass/kiosk-app             # one repo
  ./scan-github.sh courtpass DGKIorg getclickify   # several orgs
  ./scan-github.sh --repos-from infected.txt       # a list of repos
EOF
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repos-from)
      [ -f "${2:-}" ] || { echo "--repos-from: no such file: ${2:-}" >&2; exit 2; }
      while IFS= read -r line; do
        line="${line%%#*}"; line="$(printf '%s' "$line" | tr -d '[:space:]')"
        [ -n "$line" ] && OWNERS+=("$line")
      done < "$2"
      shift 2 ;;
    --include-archived) INCLUDE_ARCHIVED=1; shift ;;
    --include-forks)    INCLUDE_FORKS=1; shift ;;
    --dry-run-github)
      [ "$MODE" = "scan" ] || { echo "Choose only one remediation mode" >&2; exit 2; }
      MODE="dry-run-github"; shift ;;
    --clean-github)
      [ "$MODE" = "scan" ] || { echo "Choose only one remediation mode" >&2; exit 2; }
      MODE="clean-github"; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) OWNERS+=("$1"); shift ;;
  esac
done

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; CYN=""; DIM=""; BLD=""; RST=""
fi

command -v gh   >/dev/null 2>&1 || { echo "${RED}gh CLI required (brew install gh; gh auth login)${RST}"; exit 1; }
command -v file >/dev/null 2>&1 || { echo "${RED}file command required${RST}"; exit 1; }
command -v base64 >/dev/null 2>&1 || { echo "${RED}base64 command required${RST}"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "${RED}gh not authenticated — run: gh auth login${RST}"; exit 1; }

ARTIFACT_RE='temp_interactive_push\.bat|temp_auto_push\.bat|branch_structure\.json'
ARTIFACT_PATH_RE='(^|/)(temp_interactive_push\.bat|temp_auto_push\.bat|branch_structure\.json)$'
CONFIG_TARGET_RE='(^|/)(next\.config\.[^/]+|postcss\.config\.[^/]+|tailwind\.config\.[^/]+|config\.bat)$'
TASKS_TARGET_RE='(^|/)\.vscode/tasks\.json$'
FONT_TARGET_RE='(^|/)public/fonts/[^/]+\.(woff2?|ttf|eot|otf)$'
SPELLRIGHT_PATH_RE='(^|/)\.vscode/spellright\.dict$'
EXTJSON_PATH_RE='(^|/)\.vscode/extensions\.json$'
SETTINGS_PATH_RE='(^|/)\.vscode/settings\.json$'
AUTOTASK_RE='"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*(true|"on")'
MARKER='lzcdrtfxyqiplpd'
SUSPECT_EXT='myml\.vscode-markdown-plantuml-preview'

INFECTED_TOTAL=0
REPOS=0
BRANCHES=0
CONFIGS_CHECKED=0
SCAN_INCOMPLETE=0
CLEANED_TOTAL=0
FAILED_TOTAL=0
MANUAL_TOTAL=0

INFECTED_REPOS="$(mktemp)"
FINDINGS="$(mktemp)"
ERR_LIST="$(mktemp)"
TMP_ITEMS=()
cleanup_tmp() {
  rm -f "$INFECTED_REPOS" "$FINDINGS" "$ERR_LIST"
  local x
  for x in "${TMP_ITEMS[@]:-}"; do [ -n "$x" ] && rm -rf "$x"; done
}
trap cleanup_tmp EXIT

new_tmp() {
  local t
  t="$(mktemp)"
  TMP_ITEMS+=("$t")
  printf '%s' "$t"
}

report() {
  local repo="$1" branch="$2" branch_sha="$3" path="$4" blob_sha="$5" kind="$6" reason="$7"
  INFECTED_TOTAL=$((INFECTED_TOTAL+1))
  printf "    ${RED}%-9s${RST} ${CYN}%s@%s${RST}  %s  ${YEL}[%s]${RST}\n" "INFECTED" "$repo" "$branch" "$path" "$reason"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$repo" "$branch" "$branch_sha" "$path" "$blob_sha" "$kind" "$reason" >> "$FINDINGS"
  echo "$repo" >> "$INFECTED_REPOS"
}

# Fetch a git blob by SHA and decode it to a local temporary file.
# This downloads only that file blob; it never clones/checks out a repository.
fetch_blob_sha() {
  local repo="$1" blob_sha="$2" out="$3" encoded
  encoded="$(gh api "repos/$repo/git/blobs/$blob_sha" --jq '.content' 2>/dev/null)" || return 1
  [ -n "$encoded" ] || return 1
  printf '%s' "$encoded" | tr -d '\n' | base64 --decode > "$out" 2>/dev/null || return 1
}

# Fetch a repository file at a specific ref (commit SHA or branch) and write raw bytes.
# Also prints the file blob SHA to stdout when successful.
fetch_file_at_ref() {
  local repo="$1" path="$2" ref="$3" out="$4" sha content
  sha="$(gh api -X GET "repos/$repo/contents/$path" -f ref="$ref" --jq '.sha' 2>/dev/null || true)"
  [ -n "$sha" ] || return 1
  content="$(gh api -X GET "repos/$repo/contents/$path" -f ref="$ref" --jq '.content // empty' 2>/dev/null || true)"
  [ -n "$content" ] || return 1
  printf '%s' "$content" | tr -d '\n' | base64 --decode > "$out" 2>/dev/null || return 1
  printf '%s' "$sha"
}

# True only for a RUN of consecutive variation selectors. One byte of hidden
# code == one selector, so a real payload yields runs of hundreds; an isolated
# selector is usually an emoji modifier or a BOM. Requiring a run removes the
# false positives a single-character test produces.
# perl is mandatory here: BSD grep on macOS cannot match these high-byte ranges
# in a bracket expression and silently reports every file as clean.
VS_RUN_MIN="${VS_RUN_MIN:-8}"
has_glassworm_unicode_file() {
  local f="$1"
  command -v perl >/dev/null 2>&1 || return 1
  perl -e '
    my $n = shift @ARGV;
    open(my $fh, "<:raw", $ARGV[0]) or exit 1;
    local $/; my $s = <$fh>; close $fh;
    exit(($s =~ /(?:\xEF\xB8[\x80-\x8F]|\xF3\xA0[\x84-\x87][\x80-\xBF]){$n,}/) ? 0 : 1);
  ' "$VS_RUN_MIN" "$f" 2>/dev/null
}

config_reasons_file() {
  local f="$1" reason="" h esc_count
  h="$(grep -Eio "$ARTIFACT_RE|fa-solid-400\.woff2|public/fonts" "$f" 2>/dev/null | sort -u | paste -sd ',' -)"
  [ -n "$h" ] && reason="known-marker:$h"

  if has_glassworm_unicode_file "$f"; then
    reason="${reason:+$reason,}invisible-unicode-payload"
  fi
  if grep -Eqi 'codePointAt[[:space:]]*\(' "$f" && grep -Eqi '0xFE00|0xFE0F|0xE0100|0xE01EF' "$f"; then
    reason="${reason:+$reason,}glassworm-unicode-decoder"
  fi
  if grep -Eq '[[:blank:]]{120,}' "$f"; then
    reason="${reason:+$reason,}hidden-after-long-whitespace"
  fi
  if awk 'length($0) > 2000 { found=1; exit } END { exit !found }' "$f"; then
    reason="${reason:+$reason,}very-long-line"
  fi
  if grep -Eqi 'child_process|node:child_process' "$f" \
     && grep -Eqi 'exec(Sync)?[[:space:]]*\(|execFile(Sync)?[[:space:]]*\(|spawn(Sync)?[[:space:]]*\(' "$f"; then
    reason="${reason:+$reason,}process-exec"
  fi
  if grep -Eqi 'eval[[:space:]]*\(' "$f"; then
    reason="${reason:+$reason,}dynamic-eval"
  fi
  if grep -Eqi '(^|[^[:alnum:]_$])Function[[:space:]]*\(' "$f"; then
    reason="${reason:+$reason,}function-constructor"
  fi
  if grep -Eqi 'Buffer\.from|atob[[:space:]]*\(|fromCharCode[[:space:]]*\(|charCodeAt[[:space:]]*\(|codePointAt[[:space:]]*\(' "$f" \
     && grep -Eqi 'eval[[:space:]]*\(|Function[[:space:]]*\(' "$f"; then
    reason="${reason:+$reason,}decode-and-execute"
  fi
  esc_count="$(grep -Eo '\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}' "$f" 2>/dev/null | wc -l | tr -d ' ')"
  [ "${esc_count:-0}" -ge 12 ] && reason="${reason:+$reason,}dense-escaped-bytes"

  if grep -Eqi '(^|[^[:alnum:]_])(fetch|https?\.get|request)[[:space:]]*\(' "$f" \
     && grep -Eqi 'eval[[:space:]]*\(|Function[[:space:]]*\(|child_process|exec(Sync)?[[:space:]]*\(' "$f"; then
    reason="${reason:+$reason,}network-and-execute"
  fi

  printf '%s' "$reason"
}

tasks_reasons_file() {
  local f="$1" reason=""
  if grep -Eq 'folderOpen' "$f" && grep -Eq 'node[^\"]*\.(woff2?|ttf|eot|otf)|public/fonts' "$f"; then
    reason="tasks.json:folderOpen+font-exec"
  fi
  printf '%s' "$reason"
}

gitignore_reasons_file() {
  local f="$1"
  grep -Eo "$ARTIFACT_RE" "$f" 2>/dev/null | sort -u | paste -sd ',' -
}

font_reasons_file() {
  local f="$1" path="$2" base ft reason=""
  base="${path##*/}"
  ft="$(file -b "$f" 2>/dev/null || true)"
  echo "$ft" | grep -Eqi 'text|ascii|empty' && reason="text-not-binary"
  [ "$base" = "fa-solid-400.woff2" ] && reason="${reason:+$reason,}known-payload-name"
  printf '%s' "$reason"
}

config_bat_extra_reason() {
  local f="$1"
  local r=""
  if grep -Eqi 'powershell|curl([[:space:]]|\.exe)|wget([[:space:]]|\.exe)|certutil|bitsadmin|node([[:space:]]|\.exe)|mshta|rundll32' "$f"; then
    r='bat-download-or-exec'
  fi
  # author-spoofing push helper: clock roll + amend + forced push
  if grep -Eqi 'commit[[:space:]]+--amend|--no-verify|push[[:space:]]+-[a-z]*f|Set-Date|user\.(name|email)' "$f"; then
    r="${r:+$r,}bat-author-spoof-or-force-push"
  fi
  printf '%s' "$r"
}

# Prints KIND<TAB>REASON when the candidate is infected; prints nothing if clean.
inspect_candidate() {
  local path="$1" f="$2" kind="" reason="" extra=""

  if [[ "$path" =~ $ARTIFACT_PATH_RE ]]; then
    kind="artifact"; reason="known-glassworm-helper-file"
  elif [[ "$path" =~ $SPELLRIGHT_PATH_RE ]]; then
    kind="artifact"; reason="worm-kit-file(spellright.dict)"
  elif [[ "$path" =~ $EXTJSON_PATH_RE ]]; then
    grep -Eq "$SUSPECT_EXT" "$f" 2>/dev/null && { kind="extjson"; reason="recommends-suspect-extension"; }
  elif [[ "$path" =~ $SETTINGS_PATH_RE ]]; then
    grep -Eq "$AUTOTASK_RE" "$f" 2>/dev/null && { kind="settings"; reason="allowAutomaticTasks-bypass"; }
    if grep -Eq '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" 2>/dev/null; then
      kind="settings"; reason="${reason:+$reason,}embedded-folderOpen-task"
    fi
  elif [[ "$path" =~ $TASKS_TARGET_RE ]]; then
    reason="$(tasks_reasons_file "$f")"; [ -n "$reason" ] && kind="tasks"
  elif [[ "$path" =~ $FONT_TARGET_RE ]]; then
    reason="$(font_reasons_file "$f" "$path")"; [ -n "$reason" ] && kind="font"
  elif [[ "$path" == *.gitignore ]]; then
    reason="$(gitignore_reasons_file "$f")"; [ -n "$reason" ] && { kind="gitignore"; reason="gitignore:$reason"; }
  elif [[ "$path" =~ $CONFIG_TARGET_RE ]]; then
    reason="$(config_reasons_file "$f")"
    if [[ "$path" == */config.bat || "$path" == config.bat ]]; then
      extra="$(config_bat_extra_reason "$f")"
      [ -n "$extra" ] && reason="${reason:+$reason,}$extra"
    fi
    [ -n "$reason" ] && { kind="config"; reason="config:$reason"; }
  fi

  # ForceMemo wave marker — applies to every fetched candidate
  if grep -q "$MARKER" "$f" 2>/dev/null; then
    reason="${reason:+$reason,}forcememo-marker"
    [ -n "$kind" ] || kind="config"
  fi

  [ -n "$kind" ] && printf '%s\t%s' "$kind" "$reason"
}

# Returns success when file bytes are clean for the requested remediation kind.
file_clean_for_kind() {
  local f="$1" path="$2" kind="$3" reason="" extra="" ft
  grep -q "$MARKER" "$f" 2>/dev/null && return 1
  case "$kind" in
    config)
      reason="$(config_reasons_file "$f")"
      if [[ "$path" == */config.bat || "$path" == config.bat ]]; then
        extra="$(config_bat_extra_reason "$f")"
        [ -n "$extra" ] && reason="${reason:+$reason,}$extra"
      fi
      [ -z "$reason" ] ;;
    tasks)
      [ -z "$(tasks_reasons_file "$f")" ] ;;
    gitignore)
      [ -z "$(gitignore_reasons_file "$f")" ] ;;
    extjson)
      ! grep -Eq "$SUSPECT_EXT" "$f" 2>/dev/null ;;
    settings)
      ! grep -Eq "$AUTOTASK_RE" "$f" 2>/dev/null \
        && ! grep -Eq '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" 2>/dev/null ;;
    font)
      ft="$(file -b "$f" 2>/dev/null || true)"
      ! echo "$ft" | grep -Eqi 'text|ascii|empty' ;;
    *) return 1 ;;
  esac
}

# Scan one branch using GitHub's recursive Git tree API.
scan_branch() {
  local repo="$1" branch="$2" commit_sha="$3" tree_sha tree_data truncated path blob_sha f inspected kind reason

  tree_sha="$(gh api "repos/$repo/git/commits/$commit_sha" --jq '.tree.sha' 2>/dev/null || true)"
  if [ -z "$tree_sha" ]; then
    printf "    ${YEL}WARN${RST} %s@%s: could not read commit tree\n" "$repo" "$branch"
    echo "$repo@$branch (commit tree unavailable)" >> "$ERR_LIST"
    SCAN_INCOMPLETE=1
    return 0
  fi

  tree_data="$(new_tmp)"
  # First row is metadata; remaining rows are PATH<TAB>BLOB_SHA.
  if ! gh api -X GET "repos/$repo/git/trees/$tree_sha" -f recursive=1 \
        --jq '["__TRUNCATED__", (.truncated|tostring)], (.tree[] | select(.type == "blob") | [.path,.sha]) | @tsv' \
        > "$tree_data" 2>/dev/null; then
    printf "    ${YEL}WARN${RST} %s@%s: tree API failed\n" "$repo" "$branch"
    echo "$repo@$branch (tree API failed)" >> "$ERR_LIST"
    SCAN_INCOMPLETE=1
    return 0
  fi

  truncated="$(awk -F '\t' '$1=="__TRUNCATED__" {print $2; exit}' "$tree_data")"
  if [ "$truncated" = "true" ]; then
    printf "    ${YEL}WARN${RST} %s@%s: GitHub recursive tree was truncated; scan is incomplete for this branch\n" "$repo" "$branch"
    echo "$repo@$branch (recursive tree truncated)" >> "$ERR_LIST"
    SCAN_INCOMPLETE=1
  fi

  while IFS=$'\t' read -r path blob_sha; do
    [ "$path" = "__TRUNCATED__" ] && continue
    [ -n "$path" ] && [ -n "$blob_sha" ] || continue

    # Only fetch candidate blobs; all other files remain server-side.
    if [[ "$path" =~ $ARTIFACT_PATH_RE || "$path" =~ $TASKS_TARGET_RE || "$path" =~ $FONT_TARGET_RE \
       || "$path" =~ $SPELLRIGHT_PATH_RE || "$path" =~ $EXTJSON_PATH_RE || "$path" =~ $SETTINGS_PATH_RE \
       || "$path" == *.gitignore || "$path" =~ $CONFIG_TARGET_RE ]]; then
      if [[ "$path" =~ $CONFIG_TARGET_RE ]]; then CONFIGS_CHECKED=$((CONFIGS_CHECKED+1)); fi
      f="$(new_tmp)"
      if ! fetch_blob_sha "$repo" "$blob_sha" "$f"; then
        printf "    ${YEL}WARN${RST} %s@%s %s: could not fetch blob\n" "$repo" "$branch" "$path"
        echo "$repo@$branch:$path (blob fetch failed)" >> "$ERR_LIST"
        SCAN_INCOMPLETE=1
        rm -f "$f"
        continue
      fi
      inspected="$(inspect_candidate "$path" "$f")"
      rm -f "$f"
      [ -n "$inspected" ] || continue
      kind="${inspected%%$'\t'*}"
      reason="${inspected#*$'\t'}"
      report "$repo" "$branch" "$commit_sha" "$path" "$blob_sha" "$kind" "$reason"
    fi
  done < "$tree_data"
}

# Find the newest version of PATH in BRANCH history that passes the scanner.
# Prints: COMMIT_SHA<TAB>BLOB_SHA<TAB>TEMP_FILE
find_clean_history() {
  local repo="$1" branch="$2" path="$3" kind="$4" commit f blob_sha

  while IFS= read -r commit; do
    [ -n "$commit" ] || continue
    f="$(new_tmp)"
    blob_sha="$(fetch_file_at_ref "$repo" "$path" "$commit" "$f" || true)"
    if [ -n "$blob_sha" ] && file_clean_for_kind "$f" "$path" "$kind"; then
      printf '%s\t%s\t%s' "$commit" "$blob_sha" "$f"
      return 0
    fi
    rm -f "$f"
  done < <(gh api --paginate -X GET "repos/$repo/commits" \
            -f sha="$branch" -f path="$path" -f per_page=100 \
            --jq '.[].sha' 2>/dev/null)
  return 1
}

encode_file_base64() {
  base64 < "$1" | tr -d '\n'
}

api_update_file() {
  local repo="$1" branch="$2" path="$3" current_sha="$4" source_file="$5" source_commit="$6" content message
  content="$(encode_file_base64 "$source_file")" || return 1
  message="Remove Glassworm malware from $path (restore ${source_commit:0:12})"
  gh api --method PUT "repos/$repo/contents/$path" \
    -f message="$message" -f content="$content" -f sha="$current_sha" -f branch="$branch" \
    --jq '.commit.sha' 2>/dev/null
}

api_delete_file() {
  local repo="$1" branch="$2" path="$3" current_sha="$4" reason="$5" message
  message="Remove Glassworm malware artifact $path"
  gh api --method DELETE "repos/$repo/contents/$path" \
    -f message="$message" -f sha="$current_sha" -f branch="$branch" \
    --jq '.commit.sha' 2>/dev/null
}

api_write_transformed_gitignore() {
  local repo="$1" branch="$2" path="$3" current_sha="$4" current_file="$5" cleaned content message tmp
  tmp="$(new_tmp)"
  grep -Ev "$ARTIFACT_RE" "$current_file" > "$tmp" || true
  content="$(encode_file_base64 "$tmp")" || return 1
  message="Remove Glassworm helper entries from $path"
  gh api --method PUT "repos/$repo/contents/$path" \
    -f message="$message" -f content="$content" -f sha="$current_sha" -f branch="$branch" \
    --jq '.commit.sha' 2>/dev/null
}

verify_current_file_clean() {
  local repo="$1" branch="$2" path="$3" kind="$4" f sha
  f="$(new_tmp)"
  sha="$(fetch_file_at_ref "$repo" "$path" "$branch" "$f" || true)"
  [ -n "$sha" ] || return 1
  file_clean_for_kind "$f" "$path" "$kind"
}

verify_current_file_missing() {
  local repo="$1" branch="$2" path="$3"
  ! gh api -X GET "repos/$repo/contents/$path" -f ref="$branch" >/dev/null 2>&1
}

remediate_finding() {
  local repo="$1" branch="$2" branch_sha="$3" path="$4" current_blob="$5" kind="$6" reason="$7"
  local hist clean_commit clean_blob clean_file current_file current_sha commit_sha ft

  printf "  ${BLD}%s@%s${RST}  %s\n" "$repo" "$branch" "$path"
  printf "      detected: %s\n" "$reason"

  hist=""
  case "$kind" in
    config|tasks|gitignore|font|extjson|settings)
      hist="$(find_clean_history "$repo" "$branch" "$path" "$kind" || true)" ;;
  esac

  if [ -n "$hist" ]; then
    clean_commit="${hist%%$'\t'*}"
    hist="${hist#*$'\t'}"
    clean_blob="${hist%%$'\t'*}"
    clean_file="${hist#*$'\t'}"
    printf "      ${GRN}clean history:${RST} %s\n" "${clean_commit:0:12}"

    if [ "$MODE" = "dry-run-github" ]; then
      printf "      ${GRN}WOULD RESTORE ON GITHUB${RST} from %s\n" "${clean_commit:0:12}"
      return 0
    fi

    commit_sha="$(api_update_file "$repo" "$branch" "$path" "$current_blob" "$clean_file" "$clean_commit" || true)"
    if [ -z "$commit_sha" ]; then
      printf "      ${RED}FAILED${RST} GitHub update rejected (check branch protection/permissions)\n"
      FAILED_TOTAL=$((FAILED_TOTAL+1))
      return 0
    fi
    printf "      ${GRN}CLEANED${RST} GitHub commit %s\n" "${commit_sha:0:12}"
    if verify_current_file_clean "$repo" "$branch" "$path" "$kind"; then
      printf "      ${GRN}VERIFIED${RST} current GitHub file passes scanner\n"
      CLEANED_TOTAL=$((CLEANED_TOTAL+1))
    else
      printf "      ${RED}VERIFY FAILED${RST} file still appears suspicious; review immediately\n"
      FAILED_TOTAL=$((FAILED_TOTAL+1))
    fi
    return 0
  fi

  case "$kind" in
    artifact)
      if [ "$MODE" = "dry-run-github" ]; then
        echo "      ${GRN}WOULD DELETE ON GITHUB${RST} known helper artifact"
        return 0
      fi
      commit_sha="$(api_delete_file "$repo" "$branch" "$path" "$current_blob" "$reason" || true)"
      if [ -n "$commit_sha" ] && verify_current_file_missing "$repo" "$branch" "$path"; then
        printf "      ${GRN}DELETED + VERIFIED${RST} GitHub commit %s\n" "${commit_sha:0:12}"
        CLEANED_TOTAL=$((CLEANED_TOTAL+1))
      else
        echo "      ${RED}FAILED${RST} could not delete/verify helper artifact"
        FAILED_TOTAL=$((FAILED_TOTAL+1))
      fi
      ;;

    font)
      current_file="$(new_tmp)"
      if ! fetch_blob_sha "$repo" "$current_blob" "$current_file"; then
        echo "      ${RED}FAILED${RST} could not refetch current font"
        FAILED_TOTAL=$((FAILED_TOTAL+1)); return 0
      fi
      ft="$(file -b "$current_file" 2>/dev/null || true)"
      if echo "$ft" | grep -Eqi 'text|ascii|empty'; then
        if [ "$MODE" = "dry-run-github" ]; then
          echo "      ${GRN}WOULD DELETE ON GITHUB${RST} fake text/ASCII font (no clean history)"
          return 0
        fi
        commit_sha="$(api_delete_file "$repo" "$branch" "$path" "$current_blob" "$reason" || true)"
        if [ -n "$commit_sha" ] && verify_current_file_missing "$repo" "$branch" "$path"; then
          printf "      ${GRN}DELETED + VERIFIED${RST} GitHub commit %s\n" "${commit_sha:0:12}"
          CLEANED_TOTAL=$((CLEANED_TOTAL+1))
        else
          echo "      ${RED}FAILED${RST} could not delete/verify fake font"
          FAILED_TOTAL=$((FAILED_TOTAL+1))
        fi
      else
        echo "      ${YEL}MANUAL REVIEW${RST} binary font and no clean history; filename alone is insufficient to auto-delete"
        MANUAL_TOTAL=$((MANUAL_TOTAL+1))
      fi
      ;;

    gitignore)
      current_file="$(new_tmp)"
      current_sha="$(fetch_file_at_ref "$repo" "$path" "$branch" "$current_file" || true)"
      if [ -z "$current_sha" ]; then
        echo "      ${RED}FAILED${RST} could not fetch current .gitignore"
        FAILED_TOTAL=$((FAILED_TOTAL+1)); return 0
      fi
      if [ "$MODE" = "dry-run-github" ]; then
        echo "      ${GRN}WOULD REMOVE ON GITHUB${RST} only lines referencing known helper artifacts"
        return 0
      fi
      commit_sha="$(api_write_transformed_gitignore "$repo" "$branch" "$path" "$current_sha" "$current_file" || true)"
      if [ -n "$commit_sha" ] && verify_current_file_clean "$repo" "$branch" "$path" "$kind"; then
        printf "      ${GRN}CLEANED + VERIFIED${RST} GitHub commit %s\n" "${commit_sha:0:12}"
        CLEANED_TOTAL=$((CLEANED_TOTAL+1))
      else
        echo "      ${RED}FAILED${RST} could not clean/verify .gitignore"
        FAILED_TOTAL=$((FAILED_TOTAL+1))
      fi
      ;;

    config|tasks|extjson|settings)
      echo "      ${YEL}MANUAL REVIEW${RST} no verified clean historical version; GitHub left unchanged"
      MANUAL_TOTAL=$((MANUAL_TOTAL+1))
      ;;
  esac
}

# ---- enumerate owners -----------------------------------------------------
if [ ${#OWNERS[@]} -eq 0 ]; then
  while IFS= read -r o; do [ -n "$o" ] && OWNERS+=("$o"); done \
    < <( { gh api user -q .login 2>/dev/null; gh api user/orgs --paginate -q '.[].login' 2>/dev/null; } )
fi

if [ "$MODE" = "clean-github" ]; then
  echo "${RED}${BLD}WARNING:${RST} --clean-github writes remediation commits directly to GitHub branches."
  echo "It never clones a repository locally, but it will modify infected files when a safe action is available."
  echo
fi

echo "${BLD}GlassWorm GitHub API sweep${RST}"
echo "Targets: ${OWNERS[*]}"
echo "Mode: $MODE"
echo "Repository clones: none"
echo "Started: $(date)   (archived=$([ "$INCLUDE_ARCHIVED" = 1 ] && echo yes || echo no), forks=$([ "$INCLUDE_FORKS" = 1 ] && echo yes || echo no))"
echo

# Emit "NAME<TAB>ARCHIVED<TAB>FORK" rows for a target that is either OWNER or OWNER/REPO.
list_target_repos() {
  local t="$1"
  if [[ "$t" == */* ]]; then
    gh api "repos/$t" \
      --jq '[.full_name,(.archived|tostring),(.fork|tostring)] | @tsv' 2>/dev/null
  else
    gh repo list "$t" --limit 1000 --json nameWithOwner,isArchived,isFork \
      -q '.[] | [.nameWithOwner,(.isArchived|tostring),(.isFork|tostring)] | @tsv' 2>/dev/null
  fi
}

for owner in "${OWNERS[@]}"; do
  printf "${BLD}== %s ==${RST}\n" "$owner"
  found_any=0
  while IFS=$'\t' read -r repo archived fork; do
    [ -z "$repo" ] && continue
    found_any=1
    # An explicitly named OWNER/REPO is always scanned, even if archived or a fork.
    if [[ "$owner" != */* ]]; then
      [ "$INCLUDE_ARCHIVED" = 0 ] && [ "$archived" = "true" ] && continue
      [ "$INCLUDE_FORKS" = 0 ] && [ "$fork" = "true" ] && continue
    fi
    REPOS=$((REPOS+1))
    printf "${DIM}  [%d] %s${RST}\n" "$REPOS" "$repo" >&2

    branch_data="$(new_tmp)"
    if ! gh api --paginate "repos/$repo/branches?per_page=100" \
          --jq '.[] | [.name,.commit.sha] | @tsv' > "$branch_data" 2>/dev/null; then
      printf "  ${YEL}WARN${RST} %s (could not list branches)\n" "$repo"
      echo "$repo (branch listing failed)" >> "$ERR_LIST"
      SCAN_INCOMPLETE=1
      continue
    fi

    while IFS=$'\t' read -r branch commit_sha; do
      [ -n "$branch" ] && [ -n "$commit_sha" ] || continue
      BRANCHES=$((BRANCHES+1))
      scan_branch "$repo" "$branch" "$commit_sha"
    done < "$branch_data"
  done < <(list_target_repos "$owner")
  if [ "$found_any" = 0 ]; then
    printf "  ${YEL}WARN${RST} no repositories resolved for target '%s' (typo, or no access)\n" "$owner"
    echo "$owner (target did not resolve)" >> "$ERR_LIST"
    SCAN_INCOMPLETE=1
  fi
  echo
done

echo "${BLD}=== Scan Summary ===${RST}"
echo "Targets: ${#OWNERS[@]}   Repos scanned: $REPOS   Branches scanned: $BRANCHES   Target configs inspected: $CONFIGS_CHECKED"
if [ -s "$ERR_LIST" ]; then
  echo "${YEL}Incomplete/error items:${RST}"
  sort -u "$ERR_LIST" | sed 's/^/  /'
fi
if [ -s "$INFECTED_REPOS" ]; then
  echo "${RED}${BLD}Infected repos ($(sort -u "$INFECTED_REPOS" | wc -l | tr -d ' ')):${RST}"
  sort -u "$INFECTED_REPOS" | sed 's/^/  /'
  echo "${RED}$INFECTED_TOTAL finding(s) total.${RST}"
else
  if [ "$SCAN_INCOMPLETE" -eq 0 ]; then
    echo "${GRN}${BLD}No infections found on GitHub.${RST}"
  else
    echo "${YEL}${BLD}No infections found in the data that could be scanned, but the scan was incomplete.${RST}"
  fi
fi

if [ "$MODE" != "scan" ] && [ -s "$FINDINGS" ]; then
  echo
  echo "${BLD}=== Direct GitHub Remediation ===${RST}"
  if [ "$MODE" = "dry-run-github" ]; then
    echo "${DIM}Dry run only: GitHub will not be changed.${RST}"
  else
    echo "${YEL}Each successful action creates a commit directly on the affected branch.${RST}"
  fi
  echo

  while IFS=$'\t' read -r repo branch branch_sha path current_blob kind reason; do
    remediate_finding "$repo" "$branch" "$branch_sha" "$path" "$current_blob" "$kind" "$reason"
  done < "$FINDINGS"

  echo
  if [ "$MODE" = "clean-github" ]; then
    echo "${BLD}=== Cleanup Summary ===${RST}"
    echo "Cleaned + verified: $CLEANED_TOTAL   Failed: $FAILED_TOTAL   Manual review: $MANUAL_TOTAL"
    if [ "$SCAN_INCOMPLETE" -ne 0 ]; then
      echo "${YEL}WARNING: some branches/files could not be scanned completely; do not treat this run as proof the organization is fully clean.${RST}"
    fi
  fi
fi

echo
echo "Finished: $(date)"

# Non-zero when findings were present, remediation failed, manual review remains,
# or the scan was incomplete. This is intentional for automation/CI use.
if [ "$MODE" = "clean-github" ]; then
  [ "$FAILED_TOTAL" -eq 0 ] && [ "$MANUAL_TOTAL" -eq 0 ] && [ "$SCAN_INCOMPLETE" -eq 0 ]
else
  [ "$INFECTED_TOTAL" -eq 0 ] && [ "$SCAN_INCOMPLETE" -eq 0 ]
fi

