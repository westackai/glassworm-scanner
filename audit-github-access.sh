#!/usr/bin/env bash
#
# glassworm/audit-github-access.sh — read-only GitHub access and capability audit.
#
# COVERAGE
#   * Safe metadata for gh authentication, account SSH/GPG/signing keys and orgs.
#   * Optional org SSO authorizations, GitHub App installations and audit logs.
#   * Optional repository deploy keys, webhooks, secret metadata and open
#     secret-scanning alerts (requested with hide_secret=true).
#   * Local credential *names/storage posture*, Git configuration overrides,
#     gh extensions, editor extensions and global npm packages with GitHub-auth
#     capability signals. Shipped malicious-extension blocklist matches are HIGH.
#
# LIMITATIONS
#   GitHub's normal-user REST APIs do not enumerate every fine-grained/classic
#   PAT, authorized application, installation, browser session, or personal
#   security-log event. This script always prints the corresponding MANUAL URLs.
#   Static capability matches mean code can request/use GitHub authentication;
#   they are REVIEW signals, not proof that a credential was accessed or stolen.
#   Use scan-credentials.sh separately to find exposed token values in files or
#   history. This script never requests token-value output or prints/hashes/stores
#   token values; authenticated API calls use gh's existing credential normally.
#
# SAFETY
#   Read-only: GitHub API calls are explicitly GET and use API 2026-03-10. No
#   report, cache or temporary file is created. Token-disclosing gh/git/keychain
#   commands are deliberately absent. Metadata is stripped of control characters.
#
# Usage:
#   ./audit-github-access.sh [--offline] [--host HOST] [--org ORG ...]
#     [--audit-log] [--repo OWNER/REPO ...] [--all-repos] [--no-editors]
#
# Exit 0: no HIGH/REVIEW items in the selected audit scope.
# Exit 1: one or more HIGH/REVIEW items require attention.
# Exit 2: fatal error or a requested audit was incomplete.
#
set -uo pipefail
export LC_ALL=C LANG=C

case "$-" in
  *x*) echo "refusing to audit credentials while shell xtrace is enabled" >&2; exit 2 ;;
esac

API_VERSION="2026-03-10"
HERE="$(cd "$(dirname "$0")" && pwd)"
USER_HOME="${HOME:-}"
OFFLINE=0
AUDIT_LOG=0
ALL_REPOS=0
NO_EDITORS=0
HOST="github.com"
HOST_SET=0
ORGS=()
REPOS=()

usage() {
  sed -n '2,34p' "$0"
}

add_org() {
  local candidate="$1" item
  for item in "${ORGS[@]+"${ORGS[@]}"}"; do [ "$item" = "$candidate" ] && return 0; done
  ORGS[${#ORGS[@]}]="$candidate"
}

add_repo() {
  local candidate="$1" item
  for item in "${REPOS[@]+"${REPOS[@]}"}"; do [ "$item" = "$candidate" ] && return 0; done
  REPOS[${#REPOS[@]}]="$candidate"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --offline) OFFLINE=1; shift ;;
    --audit-log) AUDIT_LOG=1; shift ;;
    --all-repos) ALL_REPOS=1; shift ;;
    --no-editors) NO_EDITORS=1; shift ;;
    --host)
      [ "$#" -ge 2 ] || { echo "--host requires HOST" >&2; exit 2; }
      [ "$HOST_SET" -eq 0 ] || { echo "--host may be supplied only once" >&2; exit 2; }
      HOST="$2"; HOST_SET=1; shift 2 ;;
    --org)
      [ "$#" -ge 2 ] || { echo "--org requires ORG" >&2; exit 2; }
      case "$2" in *[!A-Za-z0-9_.-]*|'') echo "invalid organization name: $2" >&2; exit 2 ;; esac
      add_org "$2"; shift 2 ;;
    --repo)
      [ "$#" -ge 2 ] || { echo "--repo requires OWNER/REPO" >&2; exit 2; }
      case "$2" in
        */*) case "$2" in *[!A-Za-z0-9_./-]*|*/*/*|/*|*/|'') echo "invalid repository: $2" >&2; exit 2 ;; esac ;;
        *) echo "invalid repository (expected OWNER/REPO): $2" >&2; exit 2 ;;
      esac
      add_repo "$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$HOST" in
  *[!A-Za-z0-9.:-]*|'') echo "invalid GitHub host: $HOST" >&2; exit 2 ;;
esac
[ "$AUDIT_LOG" -eq 0 ] || [ "${#ORGS[@]}" -gt 0 ] || {
  echo "--audit-log requires at least one --org ORG" >&2
  exit 2
}
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }

HIGH=0
REVIEW=0
INFO=0
PARTIAL=0

emit() {
  local severity="$1"
  shift
  case "$severity" in
    HIGH) HIGH=$((HIGH+1)) ;;
    REVIEW) REVIEW=$((REVIEW+1)) ;;
    *) severity="INFO"; INFO=$((INFO+1)) ;;
  esac
  printf '%-7s %s\n' "$severity" "$*"
}

incomplete() {
  PARTIAL=$((PARTIAL+1))
  printf 'INCOMPLETE %s\n' "$*" >&2
}

# Preserve normal Unicode while neutralizing ANSI, bidi and other control/format
# characters. API jq expressions below select only explicitly permitted fields.
sanitize_stream() {
  python3 -c '
import sys, unicodedata
for raw in sys.stdin.buffer:
    value = raw.decode("utf-8", "replace").rstrip("\r\n")
    value = "".join("?" if (unicodedata.category(c) in ("Cc", "Cf") and c != "\t") else c for c in value)
    print(value[:2000])
'
}

api_rows() { # label severity endpoint safe-jq
  local label="$1" severity="$2" endpoint="$3" jq_filter="$4" rows row
  if rows="$(gh api --hostname "$HOST" --method GET \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: $API_VERSION" \
      --paginate "$endpoint" --jq "$jq_filter" 2>/dev/null | sanitize_stream)"; then
    if [ -z "$rows" ]; then
      emit INFO "$label: none returned"
    else
      while IFS= read -r row; do [ -n "$row" ] && emit "$severity" "$label: $row"; done <<< "$rows"
    fi
  else
    incomplete "$label could not be read (not permitted, unavailable, or network error)"
  fi
}

echo "GitHub access and local capability audit"
echo "Host: $HOST   API: $API_VERSION   Network: $([ "$OFFLINE" -eq 1 ] && echo disabled || echo read-only GET)"
echo "Secret values: never requested or displayed"
echo

echo "== GitHub account metadata =="
if [ "$OFFLINE" -eq 1 ]; then
  emit INFO "online account metadata skipped by --offline"
  if [ "${#ORGS[@]}" -gt 0 ] || [ "${#REPOS[@]}" -gt 0 ] || [ "$ALL_REPOS" -eq 1 ] || [ "$AUDIT_LOG" -eq 1 ]; then
    incomplete "online --org/--repo/--all-repos/--audit-log requests cannot run with --offline"
  fi
elif ! command -v gh >/dev/null 2>&1; then
  incomplete "gh is required for the online audit"
else
  AUTH_JSON="$(gh auth status --hostname "$HOST" --json hosts 2>/dev/null)" || AUTH_JSON=""
  if [ -z "$AUTH_JSON" ]; then
    incomplete "gh authentication metadata unavailable for $HOST"
  else
    AUTH_ROWS="$(printf '%s' "$AUTH_JSON" | python3 -c '
import json, re, sys, unicodedata
def clean(v):
    s = str(v if v is not None else "")
    s = "".join("?" if unicodedata.category(c) in ("Cc", "Cf") else c for c in s)
    return s[:240]
def source(v):
    s = str(v or "").lower()
    if "gh_token" in s: return "environment:GH_TOKEN"
    if "github_token" in s: return "environment:GITHUB_TOKEN"
    if "keyring" in s or "keychain" in s: return "secure-keyring"
    if "config" in s: return "gh-config"
    return "present-details-withheld" if s else "not-reported"
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(2)
broad = {"repo","workflow","admin:org","admin:enterprise","delete_repo","write:packages","write:org","user"}
for host, accounts in (data.get("hosts") or {}).items():
    for account in accounts or []:
        scopes = account.get("scopes") or []
        if isinstance(scopes, str): scopes = [x.strip() for x in scopes.split(",") if x.strip()]
        state = clean(account.get("state") or "unknown")
        src = source(account.get("tokenSource"))
        needs_review = state.lower() != "success" or bool(broad.intersection(scopes)) or src.startswith("environment:")
        sev = "REVIEW" if needs_review else "INFO"
        fields = ["host="+clean(host), "login="+clean(account.get("login") or "unknown"),
                  "active="+str(bool(account.get("active"))).lower(), "state="+state,
                  "protocol="+clean(account.get("gitProtocol") or "unknown"), "source="+src,
                  "scopes="+clean(",".join(scopes) if scopes else "none-reported")]
        print(sev+"\t"+" ".join(fields))
')" || AUTH_ROWS=""
    if [ -z "$AUTH_ROWS" ]; then
      incomplete "gh authentication JSON could not be safely interpreted"
    else
      while IFS=$'\t' read -r sev details; do [ -n "$details" ] && emit "$sev" "gh-auth: $details"; done <<< "$AUTH_ROWS"
    fi
  fi

  api_rows "account SSH key (id,title,created,verified,read_only)" REVIEW \
    "/user/keys?per_page=100" \
    '.[] | [(.id|tostring),(.title//""),(.created_at//""),((.verified//false)|tostring),((.read_only//false)|tostring)] | @tsv'
  api_rows "account GPG key (id,name,key_id,created,expires,can_sign)" REVIEW \
    "/user/gpg_keys?per_page=100" \
    '.[] | [(.id|tostring),(.name//""),(.key_id//""),(.created_at//""),(.expires_at//""),((.can_sign//false)|tostring)] | @tsv'
  api_rows "account SSH signing key (id,title,created)" REVIEW \
    "/user/ssh_signing_keys?per_page=100" \
    '.[] | [(.id|tostring),(.title//""),(.created_at//"")] | @tsv'
  api_rows "organization membership (org,role,state)" INFO \
    "/user/memberships/orgs?per_page=100" \
    '.[] | [(.organization.login//""),(.role//""),(.state//"")] | @tsv'

  for org in "${ORGS[@]+"${ORGS[@]}"}"; do
    echo
    echo "== Organization: $org =="
    api_rows "$org SSO credential authorization (id,login,type,title,authorized,expires)" REVIEW \
      "/orgs/$org/credential-authorizations?per_page=100" \
      '.[] | [(.credential_id|tostring),(.login//""),(.credential_type//""),(.authorized_credential_title//""),(.credential_authorized_at//""),(.authorized_credential_expires_at//"")] | @tsv'
    api_rows "$org GitHub App installation (id,app,selection,created,updated,suspended)" REVIEW \
      "/orgs/$org/installations?per_page=100" \
      '.installations[]? | [(.id|tostring),(.app_slug//""),(.repository_selection//""),(.created_at//""),(.updated_at//""),(.suspended_at//"")] | @tsv'
    if [ "$AUDIT_LOG" -eq 1 ]; then
      # Intentionally restricted to these six fields. hashed_token and other
      # potentially sensitive event properties are never selected or printed.
      api_rows "$org audit event (action,time,repo,access_type,token_id,user_agent)" INFO \
        "/orgs/$org/audit-log?include=all&per_page=100" \
        '.[] | [(.action//""),((.created_at // .["@timestamp"] // "")|tostring),(.repo//""),(.programmatic_access_type//""),((.token_id//"")|tostring),(.user_agent//"")] | @tsv'
    fi
  done

  if [ "$ALL_REPOS" -eq 1 ]; then
    if ADMIN_REPOS="$(gh api --hostname "$HOST" --method GET \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: $API_VERSION" --paginate \
      '/user/repos?affiliation=owner,collaborator,organization_member&per_page=100' \
      --jq '.[] | select(.permissions.admin == true) | .full_name' 2>/dev/null | sanitize_stream)"; then
      if [ -z "$ADMIN_REPOS" ]; then
        emit INFO "--all-repos returned no admin repositories"
      else
        while IFS= read -r repo; do
          case "$repo" in *[!A-Za-z0-9_./-]*|*/*/*|/*|*/|'') incomplete "unsafe repository name returned by API; row skipped" ;; *) add_repo "$repo" ;; esac
        done <<< "$ADMIN_REPOS"
      fi
    else
      incomplete "--all-repos could not enumerate admin repositories"
    fi
  fi

  for repo in "${REPOS[@]+"${REPOS[@]}"}"; do
    echo
    echo "== Repository: $repo =="
    api_rows "$repo deploy key (id,title,verified,read_only,created)" REVIEW \
      "/repos/$repo/keys?per_page=100" \
      '.[] | [(.id|tostring),(.title//""),((.verified//false)|tostring),((.read_only//false)|tostring),(.created_at//"")] | @tsv'
    api_rows "$repo webhook without target URL (id,name,active,events,created,updated)" REVIEW \
      "/repos/$repo/hooks?per_page=100" \
      '.[] | [(.id|tostring),(.name//""),((.active//false)|tostring),((.events//[])|join(",")),(.created_at//""),(.updated_at//"")] | @tsv'
    api_rows "$repo Actions secret metadata (name,created,updated)" INFO \
      "/repos/$repo/actions/secrets?per_page=100" \
      '.secrets[]? | [(.name//""),(.created_at//""),(.updated_at//"")] | @tsv'
    api_rows "$repo Dependabot secret metadata (name,created,updated)" INFO \
      "/repos/$repo/dependabot/secrets?per_page=100" \
      '.secrets[]? | [(.name//""),(.created_at//""),(.updated_at//"")] | @tsv'
    api_rows "$repo Codespaces secret metadata (name,created,updated)" INFO \
      "/repos/$repo/codespaces/secrets?per_page=100" \
      '.secrets[]? | [(.name//""),(.created_at//""),(.updated_at//"")] | @tsv'
    api_rows "$repo open secret-scanning alert, secret hidden (number,type,display,validity,created,url)" HIGH \
      "/repos/$repo/secret-scanning/alerts?state=open&hide_secret=true&per_page=100" \
      '.[] | [(.number|tostring),(.secret_type//""),(.secret_type_display_name//""),(.validity//""),(.created_at//""),(.html_url//"")] | @tsv'
  done
fi

echo
echo "== Local credential posture (values are never displayed) =="
ENV_NAMES="$(python3 -c '
import os, re, unicodedata
p = re.compile(r"(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY)(_|$)|^(GH_TOKEN|GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)$", re.I)
def clean(s): return "".join("?" if unicodedata.category(c) in ("Cc","Cf") else c for c in s)[:200]
for key in sorted(k for k in os.environ.keys() if p.search(k)):
    print(clean(key))
')"
if [ -z "$ENV_NAMES" ]; then
  emit INFO "no credential-like environment variable names detected"
else
  while IFS= read -r name; do [ -n "$name" ] && emit REVIEW "credential-like environment variable name: $name (value not read)"; done <<< "$ENV_NAMES"
fi

mode_of() {
  stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null || printf 'unknown'
}

credential_file() { # path label directive-regex directive-description
  local path="$1" label="$2" regex="$3" desc="$4" mode
  [ -e "$path" ] || [ -L "$path" ] || return 0
  mode="$(mode_of "$path")"
  emit INFO "$label present; mode=$mode; contents withheld"
  if [ -L "$path" ]; then
    emit REVIEW "$label is a symbolic link; verify its target and ownership manually"
    return 0
  fi
  case "$mode" in
    *[!0-7]*|'') ;;
    *) if [ $((8#$mode & 077)) -ne 0 ]; then emit REVIEW "$label is group/world accessible (mode $mode)"; fi ;;
  esac
  if [ -f "$path" ] && [ -n "$regex" ] && grep -Eiq -- "$regex" "$path" 2>/dev/null; then
    emit INFO "$label contains $desc directive(s); values withheld"
  fi
}

if [ -n "$USER_HOME" ]; then
  credential_file "$USER_HOME/.config/gh/hosts.yml" "~/.config/gh/hosts.yml" '^[[:space:]]*oauth_token:' "GitHub authentication"
  credential_file "$USER_HOME/.netrc" "~/.netrc" '(^|[[:space:]])(machine|login|password)[[:space:]]' "netrc credential"
  credential_file "$USER_HOME/.git-credentials" "~/.git-credentials" '' ""
  credential_file "$USER_HOME/.npmrc" "~/.npmrc" '(^|:)(_authToken|_auth|_password)[[:space:]]*=' "npm authentication"
  credential_file "$USER_HOME/.pypirc" "~/.pypirc" '^[[:space:]]*(username|password)[[:space:]]*=' "package-index authentication"
  credential_file "$USER_HOME/.docker/config.json" "~/.docker/config.json" '"(auths|credsStore|credHelpers)"[[:space:]]*:' "container-registry authentication"
  credential_file "$USER_HOME/.aws/credentials" "~/.aws/credentials" '^[[:space:]]*(aws_access_key_id|aws_secret_access_key|aws_session_token)[[:space:]]*=' "AWS credential"
  credential_file "$USER_HOME/.config/gcloud/application_default_credentials.json" "gcloud application-default credentials" '"(refresh_token|client_id|client_secret|type)"[[:space:]]*:' "application credential"
  credential_file "$USER_HOME/.config/hub" "~/.config/hub" '^[[:space:]]*oauth_token:' "GitHub authentication"
  credential_file "$USER_HOME/.config/glab-cli/config.yml" "glab CLI config" '^[[:space:]]*(token|job_token):' "GitLab authentication"
  credential_file "$USER_HOME/.config/github-copilot/hosts.json" "GitHub Copilot hosts config" '"(oauth_token|token)"[[:space:]]*:' "GitHub authentication"
  credential_file "$USER_HOME/.ssh/id_rsa" "~/.ssh/id_rsa" '' ""
  credential_file "$USER_HOME/.ssh/id_ed25519" "~/.ssh/id_ed25519" '' ""
  credential_file "$USER_HOME/.ssh/id_ecdsa" "~/.ssh/id_ecdsa" '' ""
  credential_file "$USER_HOME/.ssh/id_dsa" "~/.ssh/id_dsa" '' ""
else
  incomplete "HOME is unset; known credential files and editor extensions were not inspected"
fi

echo
echo "== Global Git access configuration =="
if command -v git >/dev/null 2>&1; then
  HELPERS="$(git config --global --get-all credential.helper 2>/dev/null || true)"
  if [ -z "$HELPERS" ]; then
    emit INFO "no global credential.helper configured"
  else
    while IFS= read -r helper; do
      case "$helper" in
        '') emit INFO "credential.helper reset/empty directive present" ;;
        osxkeychain|*/git-credential-osxkeychain) emit INFO "credential.helper category: OS keychain" ;;
        manager|manager-core|*/git-credential-manager|*/git-credential-manager-core) emit INFO "credential.helper category: Git Credential Manager" ;;
        libsecret|gnome-keyring|wincred|*/git-credential-libsecret) emit INFO "credential.helper category: OS credential store" ;;
        cache|cache\ *) emit INFO "credential.helper category: in-memory cache" ;;
        store|store\ *|*/git-credential-store) emit REVIEW "credential.helper category: plaintext store (value/path withheld)" ;;
        *) emit REVIEW "credential.helper category: custom executable/configuration (value withheld)" ;;
      esac
    done <<< "$HELPERS"
  fi
  if git config --global --get-regexp '^http\..*\.extraheader$' >/dev/null 2>&1; then emit REVIEW "global http.<scope>.extraHeader present; value withheld"; fi
  if git config --global --get-regexp '^url\..*\.insteadof$' >/dev/null 2>&1; then emit REVIEW "global url.<redacted>.insteadOf present; destination withheld"; fi
  if git config --global --get-all core.hooksPath >/dev/null 2>&1; then emit REVIEW "global core.hooksPath present; value withheld"; fi
  if git config --global --get-all core.sshCommand >/dev/null 2>&1; then emit REVIEW "global core.sshCommand present; value withheld"; fi
else
  incomplete "git is unavailable; global Git access configuration was not inspected"
fi

echo
echo "== gh executable extensions =="
if command -v gh >/dev/null 2>&1; then
  if GH_EXTENSIONS="$(gh extension list 2>/dev/null | sanitize_stream)"; then
    if [ -z "$GH_EXTENSIONS" ]; then
      emit INFO "no gh extensions listed"
    else
      while IFS= read -r ext; do [ -n "$ext" ] && emit REVIEW "gh extension executable: $ext (can inherit GitHub context when invoked)"; done <<< "$GH_EXTENSIONS"
    fi
  else
    incomplete "gh extension inventory failed"
  fi
else
  emit INFO "gh is not installed; no gh extension command inventory"
fi

package_meta() { # package.json fallback-id
  python3 - "$1" "$2" <<'PY'
import json, sys, unicodedata
path, fallback = sys.argv[1:3]
def clean(v, n=180):
    s = str(v if v is not None else "")
    s = "".join("?" if unicodedata.category(c) in ("Cc", "Cf") else c for c in s)
    return s.replace("\t", " ").replace("\n", " ").replace("\r", " ")[:n]
try:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
except Exception:
    data = {}
publisher, name = data.get("publisher"), data.get("name")
ident = "%s.%s" % (publisher, name) if publisher and name else fallback
engine = (data.get("engines") or {}).get("vscode", "")
print("\t".join([clean(ident), clean(data.get("version", "unknown")), clean(engine or "not-reported")]))
PY
}

capability_signals() { # directory
  # One streaming pass per extension. Output contains signal names only; source
  # lines and file contents are never emitted. Symlinks are skipped so a hostile
  # extension cannot make the audit follow a link into a credential file.
  python3 - "$1" <<'PY'
import os, re, sys

root = sys.argv[1]
order = [
    "GitHub-auth-session",
    "GitHub-auth-provider",
    "GH_TOKEN/GITHUB_TOKEN-name",
    "@octokit",
    "GitHub/OAuth-proximity",
]
found = set()
token_name = re.compile(br"(^|[^A-Za-z0-9_])(GH_TOKEN|GITHUB_TOKEN)([^A-Za-z0-9_]|$)")
oauth = re.compile(br"(^|[^a-z])oauth([^a-z]|$)")

def near(first, second, data, distance=768):
    left = data.find(first)
    while left >= 0:
        start = max(0, left - distance)
        end = min(len(data), left + len(first) + distance)
        if second in data[start:end]:
            return True
        left = data.find(first, left + 1)
    return False

for current, dirs, files in os.walk(root, followlinks=False):
    dirs[:] = [d for d in dirs if d != ".git" and not os.path.islink(os.path.join(current, d))]
    for name in files:
        if not name.lower().endswith((".js", ".cjs", ".mjs", ".ts", ".json")):
            continue
        path = os.path.join(current, name)
        if os.path.islink(path):
            continue
        try:
            with open(path, "rb") as handle:
                tail = b""
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    data = tail + chunk
                    lower = data.lower()
                    if near(b"authentication.getsession", b"github", lower): found.add("GitHub-auth-session")
                    if near(b"registerauthenticationprovider", b"github", lower): found.add("GitHub-auth-provider")
                    if token_name.search(data): found.add("GH_TOKEN/GITHUB_TOKEN-name")
                    if b"@octokit" in lower: found.add("@octokit")
                    if oauth.search(lower) and near(b"oauth", b"github", lower): found.add("GitHub/OAuth-proximity")
                    tail = data[-1024:]
        except (OSError, PermissionError):
            continue
        if len(found) == len(order):
            break
    if len(found) == len(order):
        break

print(",".join(item for item in order if item in found), end="")
PY
}

blocklist_match() { # lowercase extension id
  local id="$1" file="$HERE/data/compromised-extensions.tsv" row
  [ -f "$file" ] || return 1
  row="$(awk -F '\t' -v id="$id" 'tolower($1)==id {print $2 " / " $3; exit}' "$file")"
  [ -n "$row" ] || return 1
  printf '%s' "$row"
}

scan_editor_root() { # label root
  local label="$1" root="$2" extdir base fallback meta id version engine id_lc blocked signals
  [ -d "$root" ] || return 0
  for extdir in "$root"/*; do
    [ -d "$extdir" ] || continue
    base="$(basename "$extdir")"
    [ "$base" = ".obsolete" ] && continue
    fallback="$(printf '%s' "$base" | sed -E 's/-[0-9]+\.[0-9]+\.[0-9]+.*$//')"
    meta="$(package_meta "$extdir/package.json" "$fallback")"
    IFS=$'\t' read -r id version engine <<< "$meta"
    id_lc="$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')"
    emit INFO "$label extension: id=$id version=$version vscode-engine=$engine"
    blocked="$(blocklist_match "$id_lc" || true)"
    [ -z "$blocked" ] || emit HIGH "$label extension $id@$version matches shipped blocklist ($blocked)"
    signals="$(capability_signals "$extdir")"
    [ -z "$signals" ] || emit REVIEW "$label extension $id@$version has GitHub-specific capability signals: $signals (capability, not proof of access)"
  done
}

echo
echo "== Installed editor extensions =="
if [ "$NO_EDITORS" -eq 0 ]; then
  if [ ! -f "$HERE/data/compromised-extensions.tsv" ]; then
    incomplete "the shipped extension blocklist is missing"
  fi
  if [ -n "$USER_HOME" ]; then
    scan_editor_root "VS Code" "$USER_HOME/.vscode/extensions"
    scan_editor_root "VS Code Insiders" "$USER_HOME/.vscode-insiders/extensions"
    scan_editor_root "VSCodium" "$USER_HOME/.vscodium/extensions"
    scan_editor_root "Cursor" "$USER_HOME/.cursor/extensions"
    scan_editor_root "Windsurf" "$USER_HOME/.windsurf/extensions"
    scan_editor_root "OpenVSX" "$USER_HOME/.openvsx/extensions"
    scan_editor_root "VS Code server" "$USER_HOME/.vscode-server/extensions"
    scan_editor_root "VS Code Insiders server" "$USER_HOME/.vscode-server-insiders/extensions"
    scan_editor_root "Cursor server" "$USER_HOME/.cursor-server/extensions"
    scan_editor_root "Windsurf server" "$USER_HOME/.windsurf-server/extensions"
    scan_editor_root "VSCodium server" "$USER_HOME/.vscodium-server/extensions"
    scan_editor_root "OpenVSCode server" "$USER_HOME/.openvscode-server/extensions"
    scan_editor_root "code-server" "$USER_HOME/.local/share/code-server/extensions"
  fi
else
  emit INFO "editor extension inventory skipped by --no-editors"
fi

echo
echo "== Global npm GitHub/auth capabilities =="
if command -v npm >/dev/null 2>&1; then
  if NPM_ROOT="$(npm root -g 2>/dev/null)"; then
    if [ ! -d "$NPM_ROOT" ]; then
      emit INFO "global npm package directory is absent or empty"
    else
    NPM_FOUND=0
    for npm_entry in "$NPM_ROOT"/*; do
      [ -d "$npm_entry" ] || continue
      case "$(basename "$npm_entry")" in
        @*) npm_candidates=("$npm_entry"/*) ;;
        *) npm_candidates=("$npm_entry") ;;
      esac
      for npm_pkg in "${npm_candidates[@]}"; do
        [ -d "$npm_pkg" ] || continue
        npm_signals="$(capability_signals "$npm_pkg")"
        [ -n "$npm_signals" ] || continue
        npm_meta="$(package_meta "$npm_pkg/package.json" "$(basename "$npm_pkg")")"
        IFS=$'\t' read -r npm_name npm_version npm_engine <<< "$npm_meta"
        emit REVIEW "global npm package $npm_name@$npm_version has GitHub-specific capability signals: $npm_signals (capability, not proof of access)"
        NPM_FOUND=$((NPM_FOUND+1))
      done
    done
    [ "$NPM_FOUND" -gt 0 ] || emit INFO "no GitHub/auth capability signals found in global npm packages"
    fi
  else
    incomplete "npm is installed but its global package directory could not be resolved"
  fi
else
  emit INFO "npm is not installed; global npm packages not applicable"
fi

echo
echo "== MANUAL account review (normal-user APIs cannot enumerate all of these) =="
WEB_BASE="https://$HOST"
echo "MANUAL fine-grained PATs: $WEB_BASE/settings/personal-access-tokens"
echo "MANUAL classic PATs:      $WEB_BASE/settings/tokens"
echo "MANUAL Applications:      $WEB_BASE/settings/applications"
echo "MANUAL installations:     $WEB_BASE/settings/installations"
echo "MANUAL SSH/GPG keys:      $WEB_BASE/settings/keys"
echo "MANUAL sessions:          $WEB_BASE/settings/sessions"
echo "MANUAL security log:      $WEB_BASE/settings/security-log"
echo "MANUAL developer apps:    $WEB_BASE/settings/developers"
for org in "${ORGS[@]+"${ORGS[@]}"}"; do
  echo "MANUAL $org installations: $WEB_BASE/organizations/$org/settings/installations"
done
echo "Review last-used/expiry, scope, owner and necessity; revoke first, then rotate any exposed credential."
echo "gh auth logout --hostname $HOST removes only the local gh credential; it does NOT revoke the server-side token."

echo
echo "=== Summary ==="
echo "HIGH: $HIGH   REVIEW: $REVIEW   INFO: $INFO   INCOMPLETE: $PARTIAL"
if [ "$PARTIAL" -gt 0 ]; then
  echo "Audit incomplete; resolve the INCOMPLETE items and rerun."
  exit 2
fi
if [ "$HIGH" -gt 0 ] || [ "$REVIEW" -gt 0 ]; then
  echo "Review/revoke the items above. Capability signals alone are not evidence of misuse."
  exit 1
fi
echo "No automated HIGH/REVIEW items found in the selected scope. Complete the MANUAL account review separately."
exit 0
