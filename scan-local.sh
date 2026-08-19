#!/usr/bin/env bash
#
# glassworm/scan-local.sh — GlassWorm scanner for LOCAL git clones.
#
# For every git repository found under the given roots (default: ~/Projects ~/github):
#   1. HISTORY reachable from your LOCAL branches and tags — known worm artifact
#      paths, at any directory depth.
#   2. EVERY local branch/tag TIP — live worm files, fake ASCII "fonts",
#      malicious .vscode/tasks.json (folderOpen auto-exec), poisoned .gitignore,
#      .vscode/settings.json auto-task bypass, .vscode/extensions.json pushing the
#      suspect extension, invisible-Unicode payloads, and the ForceMemo marker.
#   3. WORKING TREE (tracked + untracked) — worm helper files, fake fonts,
#      autorun tasks.json.
#
# READ-ONLY and OFFLINE: never modifies any repository and never touches the
# network (no fetch/clone/pull/ls-remote/checkout). It only reads objects that
# are already in each local .git. A branch that exists only on the remote and
# was never fetched is invisible to it — by design.
#
# By default it scans ONLY your local branches (refs/heads) and local tags
# (refs/tags). Cached remote-tracking refs (refs/remotes/*) are skipped unless
# you pass --include-remote-refs (which is still fully offline).
#
# Exit 1 when findings exist (CI-friendly).
#
# Usage:
#   ./scan-local.sh [--tsv FILE] [--include-remote-refs] [--deep] [ROOT ...]
#
# Options:
#   --tsv FILE              also write findings as TSV to FILE
#   --include-remote-refs   also scan cached remote-tracking refs (still offline)
#   --deep                  ALSO scan dependencies (package-lock/yarn/requirements/
#                           node_modules/.venv) against the known-malicious package
#                           database. Offline.
#
# Exposed credentials are NOT scanned here — that is a separate concern with a
# separate tool: ./scan-credentials.sh
#
set -uo pipefail
export LC_ALL=C LANG=C

# Belt and braces for the offline guarantee. Nothing in this script invokes a
# network-capable git subcommand, but if a future edit ever did, these make it
# fail immediately and silently rather than hang, prompt, or reach the network.
export GIT_TERMINAL_PROMPT=0      # never prompt for credentials
export GIT_ASKPASS=/usr/bin/true  # never pop a credential helper
export GIT_SSH_COMMAND='/usr/bin/false'  # any ssh transport fails instantly
export GIT_HTTP_LOW_SPEED_LIMIT=1 GIT_HTTP_LOW_SPEED_TIME=1
export GIT_OPTIONAL_LOCKS=0       # do not take index locks; never mutate a repo

MARKER='lzcdrtfxyqiplpd'
SUSPECT_EXT='myml.vscode-markdown-plantuml-preview'
ARTIFACT_RE='(^|/)(temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)$'
SPELLRIGHT_RE='(^|/)\.vscode/spellright\.dict$'
FONT_RE='(^|/)(public/)?fonts/[^/]+\.(woff2?|ttf|eot|otf)$'
FAKE_FONT_NAME='fa-solid-400.woff2'
TASKS_RE='(^|/)\.vscode/tasks\.json$'
EXTJSON_RE='(^|/)\.vscode/extensions\.json$'
SETTINGS_RE='(^|/)\.vscode/settings\.json$'
GITIGNORE_RE='(^|/)\.gitignore$'
# Any hand-written config file is a candidate for the appended-payload trick.
CONFIG_RE='(^|/)([a-zA-Z0-9._-]+\.config\.(js|mjs|cjs|ts|mts|cts)|next\.config\.[^/]+|postcss\.config\.[^/]+|tailwind\.config\.[^/]+|vite\.config\.[^/]+|svelte\.config\.[^/]+|nuxt\.config\.[^/]+|astro\.config\.[^/]+|config\.bat)$'

# Minimum run of spaces/tabs before code to call a file "padded to hide a
# payload". Validated against 1117 real tracked source files across these orgs:
# it matched 10 files, and every one was a confirmed infection — no false
# positives. Minified bundles use long LINES, not long SPACE RUNS, so they do
# not trip it.
#
# MUST stay <= 255: git grep's regex engine rejects a repetition count above
# that with "maximum repetition exceeds 255" — a fatal error that, with stderr
# silenced, makes the sweep quietly do nothing.
PAD_MIN=200

# Strong, low-false-positive content markers for this campaign's obfuscator.
# Swept across EVERY tracked file with one `git grep`, so the payload is found
# even when it is appended to a file we would not otherwise inspect.
PAYLOAD_MARKERS=(
  'lzcdrtfxyqiplpd'            # ForceMemo wave marker
  'rmcej%otb%'                 # PolinRider obfuscator marker
  'Cot%3t=shtP'                # PolinRider obfuscator marker
  'String.fromCharCode(127)'   # separator used by this loader family
)
ARTIFACT_GREP='temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json'

# History pathspecs (git glob magic; **/ matches any depth incl. root)
HIST_PATHSPECS=(
  ':(glob)**/temp_auto_push.bat'
  ':(glob)**/temp_interactive_push.bat'
  ':(glob)**/branch_structure.json'
  ':(glob)**/fa-solid-400.woff2'
  ':(glob)**/.vscode/spellright.dict'
  ':(glob)**/config.bat'
)

TSV=""
ROOTS=()
INCLUDE_REMOTE_REFS=0    # default: pure local — only refs/heads + refs/tags
DEEP=0                   # --deep: also scan dependencies against the malicious-package DB
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tsv) TSV="${2:?--tsv needs a file}"; shift 2 ;;
    --include-remote-refs) INCLUDE_REMOTE_REFS=1; shift ;;
    --deep) DEEP=1; shift ;;
    -h|--help)
      sed -n '2,24p' "$0"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) ROOTS+=("$1"); shift ;;
  esac
done
[ ${#ROOTS[@]} -gt 0 ] || ROOTS=("$HOME/Projects" "$HOME/github")
[ -n "$TSV" ] && : > "$TSV"

# This scanner NEVER touches the network: no fetch, clone, pull, ls-remote, or
# checkout. It only reads objects already present in each local .git directory.
#
# By default it inspects ONLY your local branches (refs/heads) and local tags
# (refs/tags) — nothing that lives only on a remote. The remote-tracking refs
# (refs/remotes/*, e.g. origin/main) are cached copies of the remote's state
# from your last fetch; reading them is still offline, but they are excluded by
# default because they are not "your" local branches. Pass --include-remote-refs
# to also scan those cached remote-tracking tips (still no network).
if [ "$INCLUDE_REMOTE_REFS" = 1 ]; then
  REF_NAMESPACES=(refs/heads refs/remotes refs/tags)
  HIST_REF_FLAGS=(--all)                    # branches + remotes + tags
else
  REF_NAMESPACES=(refs/heads refs/tags)
  HIST_REF_FLAGS=(--branches --tags)        # local branches + local tags only
fi

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'
else RED=""; GRN=""; YEL=""; CYN=""; DIM=""; BLD=""; RST=""; fi

FINDINGS_TOTAL=0
REPOS_SCANNED=0
INFECTED_LIST="$(mktemp)"
trap 'rm -f "$INFECTED_LIST"' EXIT

report() { # repo where path reason
  FINDINGS_TOTAL=$((FINDINGS_TOTAL+1))
  printf "  ${RED}%-8s${RST} ${CYN}%s${RST}  %s  ${YEL}[%s]${RST}\n" "FOUND" "$2" "$3" "$4"
  [ -n "$TSV" ] && printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$TSV"
  echo "$1" >> "$INFECTED_LIST"
}

# True only for a RUN of consecutive variation selectors — the invisible-Unicode
# payload encodes one byte per selector, so it produces runs of hundreds. A lone
# selector is almost always benign (an emoji variation selector, a BOM, a
# zero-width space in a test fixture), which is why a single-character test
# generates false positives. Byte-level match so invalid UTF-8 cannot abort it.
# Note: BSD grep on macOS cannot match these byte ranges at all, so this must
# stay in perl — a grep version silently reports everything as clean.
VS_RUN_MIN="${VS_RUN_MIN:-8}"
has_invisible_unicode() { # file
  perl -e '
    my $n = shift @ARGV;
    open(my $fh, "<:raw", $ARGV[0]) or exit 1;
    local $/; my $s = <$fh>; close $fh;
    exit(($s =~ /(?:\xEF\xB8[\x80-\x8F]|\xF3\xA0[\x84-\x87][\x80-\xBF]){$n,}/) ? 0 : 1);
  ' "$VS_RUN_MIN" "$1" 2>/dev/null
}

# Heuristics for source/config files carrying an APPENDED obfuscated payload.
# This is how the worm hides in postcss.config.mjs / next.config.* etc: the real
# config is left intact, then `export default config;` is followed by hundreds of
# spaces so the payload sits far off-screen on one enormous line. It uses NO
# invisible Unicode, so the variation-selector test never fires on it.
padded_payload_reasons() { # file -> prints reasons
  local f="$1" r="" maxlen wsrun
  # obfuscator fingerprints seen in this campaign (PolinRider / obfuscator.io)
  grep -qF 'rmcej%otb%' "$f" 2>/dev/null && r="polinrider-marker"
  grep -qF 'Cot%3t=shtP' "$f" 2>/dev/null && r="${r:+$r,}polinrider-marker2"
  grep -Eq '_\$_[0-9a-f]{4,}' "$f" 2>/dev/null && r="${r:+$r,}obfuscator-var-pattern"
  grep -Eq "global\[[^]]*\][[:space:]]*=[[:space:]]*require" "$f" 2>/dev/null \
    && r="${r:+$r,}global-require-hijack"
  grep -qF 'String.fromCharCode(127)' "$f" 2>/dev/null && r="${r:+$r,}fromCharCode-127-decoder"
  # a long whitespace run used to push code off-screen
  wsrun="$(grep -oE '[[:blank:]]{120,}' "$f" 2>/dev/null | head -1 | wc -c | tr -d ' ')"
  [ "${wsrun:-0}" -gt 120 ] && r="${r:+$r,}hidden-after-long-whitespace"
  # an enormous single line in a hand-written config
  maxlen="$(awk '{ if (length($0)>m) m=length($0) } END { print m+0 }' "$f" 2>/dev/null)"
  [ "${maxlen:-0}" -gt 2000 ] && r="${r:+$r,}very-long-line($maxlen)"
  printf '%s' "$r"
}

# Content checks for a candidate blob/file. Prints reason(s) or nothing.
inspect_content() { # path file
  local path="$1" f="$2" base reason="" ft
  base="${path##*/}"
  if [[ "$path" =~ $ARTIFACT_RE ]]; then
    reason="known-glassworm-helper"
  elif [[ "$path" =~ $SPELLRIGHT_RE ]]; then
    reason="worm-kit-file(spellright.dict)"
  elif [[ "$path" =~ $FONT_RE || "$base" == "$FAKE_FONT_NAME" ]]; then
    ft="$(file -b "$f" 2>/dev/null || true)"
    echo "$ft" | grep -Eqi 'text|ascii|script|empty' && reason="fake-font-is-text"
    [ "$base" = "$FAKE_FONT_NAME" ] && reason="${reason:+$reason,}known-payload-name"
  elif [[ "$path" =~ $TASKS_RE ]]; then
    if grep -q 'folderOpen' "$f" 2>/dev/null && grep -Eq 'node[^"]*\.(woff2?|ttf|eot|otf)|public/fonts' "$f" 2>/dev/null; then
      reason="tasks.json-folderOpen-font-exec"
    fi
  elif [[ "$path" =~ $EXTJSON_RE ]]; then
    grep -q "$SUSPECT_EXT" "$f" 2>/dev/null && reason="recommends-suspect-extension"
  elif [[ "$path" =~ $SETTINGS_RE ]]; then
    # worm plants this to bypass the "allow automatic tasks?" prompt
    grep -Eq '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*(true|"on")' "$f" 2>/dev/null \
      && reason="settings.json-allowAutomaticTasks-bypass"
    if grep -Eq '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" 2>/dev/null; then
      reason="${reason:+$reason,}settings.json-embedded-folderOpen-task"
    fi
  elif [[ "$path" =~ $GITIGNORE_RE ]]; then
    local h; h="$(grep -Eo "$ARTIFACT_GREP" "$f" 2>/dev/null | sort -u | paste -sd ',' -)"
    [ -n "$h" ] && reason="gitignore-hides:$h"
  elif [[ "$path" =~ $CONFIG_RE ]]; then
    has_invisible_unicode "$f" && reason="invisible-unicode-payload"
    if grep -Eq 'codePointAt' "$f" 2>/dev/null && grep -Eq '0xFE00|0xFE0F|0xE0100|0xE01EF' "$f" 2>/dev/null; then
      reason="${reason:+$reason,}glassworm-unicode-decoder"
    fi
    # appended-after-whitespace payload (the postcss.config.mjs case)
    local pr; pr="$(padded_payload_reasons "$f")"
    [ -n "$pr" ] && reason="${reason:+$reason,}$pr"
    if [[ "$base" == config.bat ]] && grep -Eqi 'commit --amend|--no-verify|push +-[a-z]*f|Set-Date|user\.name|user\.email' "$f" 2>/dev/null; then
      reason="${reason:+$reason,}config.bat-author-spoof/push-helper"
    fi
  fi
  grep -q "$MARKER" "$f" 2>/dev/null && reason="${reason:+$reason,}forcememo-marker"
  printf '%s' "$reason"
}

is_candidate() { # path
  local p="$1" base="${1##*/}"
  [[ "$p" =~ $ARTIFACT_RE || "$p" =~ $SPELLRIGHT_RE || "$p" =~ $FONT_RE || "$base" == "$FAKE_FONT_NAME" \
     || "$p" =~ $TASKS_RE || "$p" =~ $EXTJSON_RE || "$p" =~ $SETTINGS_RE || "$p" =~ $GITIGNORE_RE || "$p" =~ $CONFIG_RE ]]
}

scan_repo() { # gitdir worktree(optional, empty for bare)
  local gd="$1" wt="${2:-}" label hist tips tip ref commit path f reason seen
  label="${wt:-$gd}"
  label="${label/#$HOME/~}"
  REPOS_SCANNED=$((REPOS_SCANNED+1))
  printf "${DIM}[%d] %s${RST}\n" "$REPOS_SCANNED" "$label" >&2

  # ---- 1. history reachable from local refs ------------------------------
  # --branches --tags = refs/heads + refs/tags (local only). With
  # --include-remote-refs this becomes --all, adding cached remote-tracking refs.
  hist="$(git --git-dir="$gd" log "${HIST_REF_FLAGS[@]}" --format= --name-only -- "${HIST_PATHSPECS[@]}" 2>/dev/null | sort -u | sed '/^$/d')"
  if [ -n "$hist" ]; then
    while IFS= read -r path; do
      report "$label" "history" "$path" "worm-artifact-in-history"
    done <<< "$hist"
  fi

  # ---- 2. every unique local branch/tag tip (+ remote-tracking if opted in)
  seen="$(mktemp)"
  while IFS=$'\t' read -r commit ref; do
    [ -n "$commit" ] || continue
    grep -qx "$commit" "$seen" && continue
    echo "$commit" >> "$seen"
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      is_candidate "$path" || continue
      f="$(mktemp)"
      if git --git-dir="$gd" cat-file blob "$commit:$path" > "$f" 2>/dev/null; then
        reason="$(inspect_content "$path" "$f")"
        [ -n "$reason" ] && report "$label" "tip:$ref" "$path" "$reason"
      fi
      rm -f "$f"
    done < <(git --git-dir="$gd" ls-tree -r --name-only "$commit" 2>/dev/null)
  done < <(git --git-dir="$gd" for-each-ref "${REF_NAMESPACES[@]}" \
             --format='%(objectname)%09%(refname:short)' 2>/dev/null \
           | while IFS=$'\t' read -r o r; do
               c="$(git --git-dir="$gd" rev-parse "$o^{commit}" 2>/dev/null)" && printf '%s\t%s\n' "$c" "$r"
             done)

  # Payload-marker sweep across all unique tips. One `git grep` covers EVERY
  # tracked file, so an appended payload is caught even in a file type we do not
  # individually inspect (the postcss.config.mjs / any-.js case).
  if [ -s "$seen" ]; then
    local gargs=()
    for m in "${PAYLOAD_MARKERS[@]}"; do gargs+=(-e "$m"); done
    while IFS= read -r hit; do
      [ -n "$hit" ] || continue
      # hit looks like "<commit>:<path>"; report the path
      report "$label" "content" "${hit#*:}" "payload-marker-in-tracked-file"
    done < <(xargs -n 32 git --git-dir="$gd" grep -I -l -F "${gargs[@]}" < "$seen" 2>/dev/null | sort -u)

    # Padding sweep: a run of PAD_MIN+ spaces/tabs followed by code is how this
    # campaign hides an appended payload off-screen. Measured on 722 real tracked
    # source files here, this matched ONLY genuine infections — no false
    # positives — because minified bundles use long lines, not long space runs.
    while IFS= read -r hit; do
      [ -n "$hit" ] || continue
      report "$label" "content" "${hit#*:}" "code-hidden-after-${PAD_MIN}+-spaces"
    done < <(xargs -n 32 git --git-dir="$gd" grep -I -l -E "[ $(printf '\t')]{$PAD_MIN}[^ $(printf '\t')]" \
               < "$seen" 2>/dev/null | sort -u)
  fi
  rm -f "$seen"

  # ---- 3. working tree (tracked + untracked) ------------------------------
  [ -n "$wt" ] && [ -d "$wt" ] && scan_files_on_disk "$wt" "$label" "worktree"

  # ---- 4. --deep: known-malicious dependencies -----------------------------
  if [ "$DEEP" = 1 ] && [ -n "$wt" ] && [ -d "$wt" ]; then
    scan_dependencies "$wt" "$label"
  fi
}

# Scan loose files on disk for worm artifacts. Used for a repo's working tree
# and also, standalone, for a folder that is not a git repo at all (an extracted
# archive, a Downloads folder, a deploy directory). Without this, pointing the
# scanner at a plain folder holding a live payload would report "0 findings".
scan_files_on_disk() { # dir label where
  local dir="$1" label="$2" where="$3" path rel reason
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    rel="${path#"$dir"/}"
    reason="$(inspect_content "$rel" "$path")"
    [ -n "$reason" ] && report "$label" "$where" "$rel" "$reason"
  done < <(find "$dir" \( -name .git -o -name node_modules -o -name .next -o -name dist -o -name build \) -prune -o \
             -type f \( -name 'temp_auto_push.bat' -o -name 'temp_interactive_push.bat' \
                        -o -name 'branch_structure.json' -o -name "$FAKE_FONT_NAME" \
                        -o -name 'tasks.json' -path '*/.vscode/*' \
                        -o -name 'extensions.json' -path '*/.vscode/*' \
                        -o -name 'settings.json' -path '*/.vscode/*' \
                        -o -name 'spellright.dict' -path '*/.vscode/*' \
                        -o -name 'config.bat' \
                        -o -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' \
                        -o -name '*.config.ts' -o -name '*.config.mts' -o -name '*.config.cts' \
                        -o \( -name '*.woff2' -path '*/fonts/*' \) -o \( -name '*.woff' -path '*/fonts/*' \) \
                        -o \( -name '*.ttf' -path '*/fonts/*' \) -o \( -name '*.eot' -path '*/fonts/*' \) \) \
             -print 2>/dev/null)

  # Marker sweep over loose files on disk — catches an appended payload in any
  # source file, including untracked ones the git sweep cannot see.
  local gargs=() m
  for m in "${PAYLOAD_MARKERS[@]}"; do gargs+=(-e "$m"); done
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    report "$label" "$where" "${hit#"$dir"/}" "payload-marker-on-disk"
  done < <(grep -rIl -F "${gargs[@]}" \
             --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.next \
             --exclude-dir=dist --exclude-dir=build --exclude-dir=vendor \
             "$dir" 2>/dev/null | sort -u)

  # Padding sweep on disk (catches untracked files the git sweep cannot see).
  # Restricted to source/config extensions so we do not walk binaries or data.
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    report "$label" "$where" "${hit#"$dir"/}" "code-hidden-after-${PAD_MIN}+-spaces"
  done < <(grep -rIl -E "[ $(printf '\t')]{$PAD_MIN}[^ $(printf '\t')]" \
             --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.jsx' \
             --include='*.ts' --include='*.tsx' --include='*.mts' --include='*.cts' \
             --include='*.json' --include='*.bat' --include='*.sh' \
             --exclude='*.min.js' --exclude='*.min.mjs' \
             --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.next \
             --exclude-dir=dist --exclude-dir=build --exclude-dir=vendor \
             "$dir" 2>/dev/null | sort -u)
}


# ---------------------------------------------------------------------------
# --deep : dependency scanning against the known-malicious package database
# ---------------------------------------------------------------------------
HERE_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DB="$HERE_DIR/data/malicious-packages.tsv"

# Is VERSION covered by SPEC?  spec: "*" | "1.2.3,1.2.4" | "1.3.0-1.3.4"
version_matches() { # spec version
  local spec="$1" v="$2" item lo hi
  [ "$spec" = "*" ] && return 0
  [ -z "$v" ] && return 1
  case "$spec" in
    *-*)
      lo="${spec%%-*}"; hi="${spec##*-}"
      [ "$(printf '%s\n%s\n' "$lo" "$v" | sort -V | head -1)" = "$lo" ] &&
      [ "$(printf '%s\n%s\n' "$v" "$hi" | sort -V | head -1)" = "$v" ] && return 0
      ;;
  esac
  IFS=',' read -ra _vs <<< "$spec"
  for item in "${_vs[@]}"; do [ "$item" = "$v" ] && return 0; done
  return 1
}

# Emit "name<TAB>version" for every dependency we can see under a directory.
enumerate_deps() { # dir
  local d="$1" f
  # npm lockfile v2/v3 (packages{} keyed by node_modules/<name>) and v1 (dependencies{})
  while IFS= read -r f; do
    python3 - "$f" <<'PYX' 2>/dev/null
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
def emit(n,v):
    if n and v: print(f"{n}\t{v}")
for k,v in (d.get('packages') or {}).items():
    if not k: continue
    name=v.get('name') or k.split('node_modules/')[-1]
    emit(name, v.get('version'))
def walk(deps):
    for n,v in (deps or {}).items():
        if isinstance(v,dict):
            emit(n, v.get('version')); walk(v.get('dependencies'))
walk(d.get('dependencies'))
PYX
  done < <(find "$d" -name package-lock.json -not -path '*/node_modules/*' 2>/dev/null)

  # installed node_modules (authoritative: what is actually on disk)
  while IFS= read -r f; do
    python3 - "$f" <<'PYX' 2>/dev/null
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
if d.get('name') and d.get('version'): print(f"{d['name']}\t{d['version']}")
PYX
  done < <(find "$d" -path '*/node_modules/*' -name package.json -maxdepth 6 2>/dev/null | head -4000)

  # yarn.lock  ("pkg@range:" then "  version \"1.2.3\"")
  while IFS= read -r f; do
    awk '/^"?[^ #].*:$/{name=$0; gsub(/^"/,"",name); sub(/@[^@]*:$/,"",name); next}
         /^  version /{gsub(/"/,"",$2); if(name!="") print name"\t"$2}' "$f" 2>/dev/null
  done < <(find "$d" -name yarn.lock -not -path '*/node_modules/*' 2>/dev/null)

  # requirements.txt  (name==version)
  while IFS= read -r f; do
    grep -E '^[A-Za-z0-9._-]+[[:space:]]*==[[:space:]]*[0-9]' "$f" 2>/dev/null |
      sed -E 's/[[:space:]]//g; s/==/\t/; s/[;#].*$//'
  done < <(find "$d" -name requirements*.txt -not -path '*/node_modules/*' 2>/dev/null)

  # installed python packages in .venv / venv
  while IFS= read -r f; do
    n=$(sed -n 's/^Name: //p' "$f" 2>/dev/null | head -1)
    v=$(sed -n 's/^Version: //p' "$f" 2>/dev/null | head -1)
    [ -n "$n" ] && [ -n "$v" ] && printf '%s\t%s\n' "$n" "$v"
  done < <(find "$d" \( -name .venv -o -name venv \) -prune -exec find {} -name METADATA -path '*.dist-info*' \; 2>/dev/null | head -4000)
}

scan_dependencies() { # dir label
  local dir="$1" label="$2"
  [ -f "$PKG_DB" ] || return 0
  local deps; deps="$(mktemp)"
  enumerate_deps "$dir" | sort -u > "$deps"
  local total; total=$(wc -l < "$deps" | tr -d ' ')
  [ "${total:-0}" -eq 0 ] && { rm -f "$deps"; return 0; }
  printf "${DIM}      %s dependencies enumerated${RST}\n" "$total" >&2

  # Single pass: load the DB into an awk hash, then stream the dependency list
  # once. The previous nested-loop version was O(db x deps) in bash and took
  # minutes per repo; this is effectively linear.
  while IFS=$'\t' read -r pname pver pcamp; do
    [ -n "$pname" ] && report "$label" "dependency" "$pname@$pver" "malicious-package($pcamp)"
  done < <(awk -F'\t' '
    function vnum(v,  a,n,i,r) { n=split(v,a,"."); r=0
      for(i=1;i<=3;i++){ x=(i<=n)?a[i]+0:0; r=r*100000+x } return r }
    NR==FNR {
      if ($0 ~ /^#/ || NF<4) next
      spec[$1]=$3; camp[$1]=$4; next
    }
    {
      name=$1; ver=$2
      if (!(name in spec)) next
      s=spec[name]
      if (s=="*") { print name "\t" ver "\t" camp[name]; next }
      if (s ~ /^[0-9][0-9.]*-[0-9]/) {          # inclusive range lo-hi
        i=index(s,"-"); lo=substr(s,1,i-1); hi=substr(s,i+1)
        if (vnum(ver)>=vnum(lo) && vnum(ver)<=vnum(hi)) print name "\t" ver "\t" camp[name]
        next
      }
      n=split(s,vs,",")                          # exact list
      for(i=1;i<=n;i++){ gsub(/^[ \t]+|[ \t]+$/,"",vs[i]); if (vs[i]==ver) { print name "\t" ver "\t" camp[name]; break } }
    }' "$PKG_DB" "$deps")
  rm -f "$deps"
}


echo "${BLD}GlassWorm local scan${RST}"
echo "Roots: ${ROOTS[*]}"
echo "Started: $(date)"
echo

# discover repos (.git may be a dir or, for worktrees/submodules, a file)
while IFS= read -r gitpath; do
  wt="$(dirname "$gitpath")"
  if [ -d "$gitpath" ]; then
    scan_repo "$gitpath" "$wt"
  elif [ -f "$gitpath" ]; then
    gd="$(sed -n 's/^gitdir: //p' "$gitpath" | head -1)"
    case "$gd" in /*) ;; *) gd="$wt/$gd" ;; esac
    [ -d "$gd" ] && scan_repo "$gd" "$wt"
  fi
done < <(find "${ROOTS[@]}" \( -name node_modules -o -name Library -o -name .Trash \) -prune -o \
           -name .git \( -type d -o -type f \) -print 2>/dev/null)

# bare mirrors (e.g. repo.git) — exclude plain ".git" dirs, which belong to the
# working-tree repos already scanned above and would otherwise be counted twice.
while IFS= read -r bare; do
  [ "$(basename "$bare")" = ".git" ] && continue
  [ -d "$bare/objects" ] && [ ! -e "$bare/.git" ] && scan_repo "$bare" ""
done < <(find "${ROOTS[@]}" -name node_modules -prune -o -type d -name '*.git' -print 2>/dev/null)

# Roots with no git repo under them are still scanned as plain files, so a
# folder that merely holds worm artifacts (extracted archive, Downloads, a
# deploy dir) cannot come back "clean" just because it is not a repo.
FILES_ONLY_ROOTS=0
for r in "${ROOTS[@]}"; do
  [ -d "$r" ] || continue
  if ! find "$r" -name node_modules -prune -o -name .git -print -quit 2>/dev/null | grep -q .; then
    FILES_ONLY_ROOTS=$((FILES_ONLY_ROOTS+1))
    printf "${DIM}[files] %s ${RST}${YEL}(no git repo here — scanning files only)${RST}\n" "${r/#$HOME/\~}" >&2
    scan_files_on_disk "$r" "${r/#$HOME/\~}" "files"
    # --deep applies to non-repo folders too: an extracted archive or a deploy
    # directory can carry a malicious lockfile / node_modules with no git at all.
    [ "$DEEP" = 1 ] && scan_dependencies "$r" "${r/#$HOME/\~}"
  fi
done

echo
echo "${BLD}=== Summary ===${RST}"
echo "Repos scanned: $REPOS_SCANNED   Non-repo folders scanned: $FILES_ONLY_ROOTS   Findings: $FINDINGS_TOTAL"
if [ -s "$INFECTED_LIST" ]; then
  echo "${RED}${BLD}Repos with findings ($(sort -u "$INFECTED_LIST" | wc -l | tr -d ' ')):${RST}"
  sort -u "$INFECTED_LIST" | sed 's/^/  /'
else
  echo "${GRN}${BLD}No GlassWorm indicators found.${RST}"
fi
[ -n "$TSV" ] && echo "TSV report: $TSV"
echo "Finished: $(date)"
[ "$FINDINGS_TOTAL" -eq 0 ]
