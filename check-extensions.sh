#!/usr/bin/env bash
#
# glassworm/check-extensions.sh — audit installed editor extensions against the
# known GlassWorm-compromised list (124 IDs, waves 1–5 + this incident).
#
# Checks VS Code, VS Code Insiders, Cursor, Windsurf, VSCodium and any OpenVSX
# client that uses the standard ~/.<editor>/extensions layout. Also greps each
# installed extension for the invisible-Unicode decoder and the wave marker,
# so a compromised extension NOT yet on the public list can still be caught.
#
# READ-ONLY. Prints uninstall commands; never removes anything itself.
#
# Usage: ./check-extensions.sh [--deep]
#          --deep   also scan every installed extension's JS for the decoder
#                   pattern and marker string (slower, catches unknown waves)
#
set -uo pipefail
export LC_ALL=C LANG=C

HERE="$(cd "$(dirname "$0")" && pwd)"
LIST="$HERE/data/compromised-extensions.tsv"
MARKER='lzcdrtfxyqiplpd'
DEEP=0
[ "${1:-}" = "--deep" ] && DEEP=1

[ -f "$LIST" ] || { echo "missing extension list: $LIST" >&2; exit 1; }

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'
else RED=""; GRN=""; YEL=""; DIM=""; BLD=""; RST=""; fi

EXT_DIRS=(
  "$HOME/.vscode/extensions"
  "$HOME/.vscode-insiders/extensions"
  "$HOME/.vscode-oss/extensions"
  "$HOME/.cursor/extensions"
  "$HOME/.windsurf/extensions"
  "$HOME/.vscodium/extensions"
  "$HOME/.openvsx/extensions"
)

# lowercase id -> "wave<TAB>source"
BAD="$(mktemp)"; trap 'rm -f "$BAD"' EXIT
grep -v '^#' "$LIST" | grep -v '^[[:space:]]*$' \
  | awk -F'\t' '{print tolower($1)"\t"$2"\t"$3}' > "$BAD"

TOTAL_INSTALLED=0
HITS=0
DEEP_HITS=0

# Bundled libraries that legitimately map Unicode variation selectors.
# U+E0100–E01EF are Ideographic Variation Selectors — any PDF/font/CJK text
# renderer handles them, so a bare "file mentions 0xE0100" is not a signal.
LEGIT_LIB_RE='(^|/)(pdf\.js|pdfjs|pdf\.worker|fontkit|opentype|harfbuzz|icu4x|unicode|grapheme|emoji-regex|twemoji)'

# Minimum run of consecutive variation selectors to call something a payload.
# Measured on real data: Unicode category tables peak at a run of 1, language
# grammars at 3; an actual invisible-Unicode payload runs into the hundreds.
VS_RUN_MIN=8

# Print the names of files containing a run of VS_RUN_MIN+ variation selectors
# from either range (they interleave — one selector encodes one byte).
# Byte-level matching, so files with invalid UTF-8 do not abort the scan.
vs_run_scan() {
  [ "$#" -gt 0 ] || return 0
  perl -e '
    my $n = shift @ARGV;
    for my $f (@ARGV) {
      open(my $fh, "<:raw", $f) or next;
      local $/; my $s = <$fh>; close $fh;
      print "$f\n" if $s =~ /(?:\xEF\xB8[\x80-\x8F]|\xF3\xA0[\x84-\x87][\x80-\xBF]){$n,}/;
    }' "$VS_RUN_MIN" "$@" 2>/dev/null
}
export VS_RUN_MIN

# Print a reason if this extension really looks like it carries the payload.
# Ordered strongest signal first. Uses cheap recursive greps to pre-filter and
# only pays for perl on the few files that actually look interesting.
deep_scan_ext() {
  local extdir="$1" f hit
  local INC=(--include='*.js' --include='*.cjs' --include='*.mjs')

  # 1. the wave marker — unambiguous
  if grep -rIlq "${INC[@]}" --include='*.json' -e "$MARKER" "$extdir" 2>/dev/null; then
    printf "wave marker '%s' in code" "$MARKER"; return
  fi

  # 2. ACTUAL invisible variation-selector characters embedded in shipped JS
  #    (not the hex constants — the real characters), as a RUN.
  #
  #    Must use perl, not grep: BSD grep on macOS silently fails to match these
  #    high-byte ranges in a bracket expression — it returns zero hits even when
  #    the bytes are present, so a grep-based check here reports "clean" always.
  local jsfiles=()
  while IFS= read -r f; do jsfiles+=("$f"); done < <(
    find "$extdir" \( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' \) -size -8M 2>/dev/null)
  if [ "${#jsfiles[@]}" -gt 0 ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      [[ "$f" =~ $LEGIT_LIB_RE ]] && continue
      printf "invisible-Unicode payload (run of %s+ variation selectors) in %s" \
        "$VS_RUN_MIN" "${f#"$extdir"/}"; return
    done < <(vs_run_scan "${jsfiles[@]}")
  fi

  # 3. decoder pattern: codePointAt within 500 chars of a variation-selector
  #    constant. Proximity is the whole point — in a real decoder they sit
  #    together; in pdf.js/fontkit the constants live far from any codePointAt.
  while IFS= read -r f; do
    [[ "$f" =~ $LEGIT_LIB_RE ]] && continue
    if perl -0777 -ne 'exit(/codePointAt\s*\([^)]*\).{0,500}(?:0xFE00|0xE0100)|(?:0xFE00|0xE0100).{0,500}codePointAt/si ? 0 : 1)' "$f" 2>/dev/null; then
      printf "invisible-Unicode decoder pattern in %s" "${f#"$extdir"/}"; return
    fi
  done < <(grep -rIl "${INC[@]}" -e '0xE0100' -e '0xe0100' -e '0xFE00' -e '0xfe00' "$extdir" 2>/dev/null)
}

echo "${BLD}GlassWorm extension audit${RST}"
echo "Known-bad list: $(wc -l < "$BAD" | tr -d ' ') extension IDs"
echo

for d in "${EXT_DIRS[@]}"; do
  [ -d "$d" ] || continue
  n=$(find "$d" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  printf "${BLD}%s${RST} ${DIM}(%s installed)${RST}\n" "${d/#$HOME/\~}" "$n"

  while IFS= read -r extdir; do
    base="$(basename "$extdir")"
    TOTAL_INSTALLED=$((TOTAL_INSTALLED+1))

    # dir name is publisher.name-version — strip the trailing -x.y.z
    id="$(printf '%s' "$base" | sed -E 's/-[0-9]+\.[0-9]+\.[0-9]+.*$//')"
    id_lc="$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')"

    if match="$(awk -F'\t' -v k="$id_lc" '$1==k {print $2"\t"$3; exit}' "$BAD")"; [ -n "$match" ]; then
      wave="${match%%$'\t'*}"; src="${match#*$'\t'}"
      printf "  ${RED}%-11s${RST} %s  ${YEL}[%s · %s]${RST}\n" "COMPROMISED" "$base" "$wave" "$src"
      printf "              ${DIM}uninstall: code --uninstall-extension %s${RST}\n" "$id"
      HITS=$((HITS+1))
    fi

    if [ "$DEEP" = 1 ]; then
      deep_reason="$(deep_scan_ext "$extdir")"
      if [ -n "$deep_reason" ]; then
        printf "  ${RED}%-11s${RST} %s  ${YEL}[%s]${RST}\n" "PAYLOAD" "$base" "$deep_reason"
        DEEP_HITS=$((DEEP_HITS+1))
      fi
    fi
  done < <(find "$d" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort)
  echo
done

echo "${BLD}=== Summary ===${RST}"
echo "Extensions inspected: $TOTAL_INSTALLED   Known-bad matches: $HITS   Payload-pattern hits: $DEEP_HITS"
if [ "$HITS" -eq 0 ] && [ "$DEEP_HITS" -eq 0 ]; then
  echo "${GRN}${BLD}No compromised extensions found.${RST}"
  [ "$DEEP" = 0 ] && echo "${DIM}(run with --deep to also scan extension code for unlisted variants)${RST}"
else
  echo "${RED}${BLD}Remove the extensions above, then rotate every credential on this machine.${RST}"
  echo "Disable extension auto-update until the all-clear:"
  echo "  \"extensions.autoUpdate\": false, \"extensions.autoCheckUpdates\": false"
fi
[ "$((HITS+DEEP_HITS))" -eq 0 ]
