#!/usr/bin/env bash
# package.sh — bundle the whole kit (source + staged exploits) into one archive to
# carry to an air-gapped engagement. Run on the connected staging box.
#
# What goes in: everything git tracks (the fieldkit package, bin/, docs,
# tests/, docs, and the exploits/ fetcher+manifest) PLUS whatever you've fetched into
# exploits/. What stays out (via .gitignore + git ls-files): .git history, __pycache__/
# *.pyc, engagement.db (loot!), prior *.tar.gz, venvs, and the nested .git dirs of any
# cloned PoC repos.
#
# Usage:
#   sh package.sh                       # -> fieldkit-YYYYMMDD.tar.gz (with staged exploits)
#   sh package.sh --fetch               # run exploits/fetch.sh first, then package
#   sh package.sh --no-exploits         # source + fetcher only (re-fetch on the far side)
#   sh package.sh -o kit.tar.gz         # choose the output name
#   sh package.sh --list                # show what would be included, build nothing
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT=""
INCLUDE_EXPLOITS=1
FETCH=0
LIST=0

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output) OUT="${2:-}"; shift ;;
        --no-exploits) INCLUDE_EXPLOITS=0 ;;
        --fetch) FETCH=1 ;;
        --list) LIST=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

have() { command -v "$1" >/dev/null 2>&1; }
have tar || { echo "tar is required" >&2; exit 2; }
have git || { echo "git is required (package.sh lists files via git)" >&2; exit 2; }

STAMP="$(date +%Y%m%d 2>/dev/null || echo bundle)"
[ -z "$OUT" ] && OUT="$ROOT/fieldkit-$STAMP.tar.gz"

if [ "$FETCH" = 1 ]; then
    echo "== fetching exploits first =="
    sh "$ROOT/exploits/fetch.sh" || echo "(fetch reported problems — continuing to package what's present)"
    echo ""
fi

# Build the file list: tracked files (gitignore already excludes loot/pyc/etc), then
# add fetched exploit artifacts (untracked, gitignored) unless --no-exploits.
FILELIST="$(mktemp)"
cleanup() { rm -f "$FILELIST"; }
trap cleanup EXIT

( cd "$ROOT" && git ls-files ) > "$FILELIST"
if [ "$INCLUDE_EXPLOITS" = 1 ]; then
    # every real file under exploits/, minus nested clone histories, pyc, and the demo
    # media/doc bloat that ships in tool repos (never functional) — keep bundles slim.
    ( cd "$ROOT" && find exploits -type f \
        -not -path '*/.git/*' -not -name '*.pyc' -not -path '*/__pycache__/*' \
        -not -iname '*.mp4' -not -iname '*.webm' -not -iname '*.mov' -not -iname '*.gif' \
        -not -path '*/screenshots/*' -not -path '*/presentations/*' \
        -not -path '*/documentation/*' ) >> "$FILELIST"
fi
# de-dup, drop empties
sort -u "$FILELIST" | sed '/^$/d' > "$FILELIST.u" && mv "$FILELIST.u" "$FILELIST"

count="$(wc -l < "$FILELIST" | tr -d ' ')"

if [ "$LIST" = 1 ]; then
    echo "would package $count files -> $(basename "$OUT")"
    echo "top-level:"; sed 's,/.*,,' "$FILELIST" | sort | uniq -c | sort -rn
    if [ "$INCLUDE_EXPLOITS" = 1 ] && [ -d "$ROOT/exploits" ]; then
        echo "exploits staged: $(du -sh "$ROOT/exploits" 2>/dev/null | cut -f1)"
    fi
    exit 0
fi

echo "== packaging $count files =="
# nest everything under fieldkit/ so extraction is tidy.
if tar czf "$OUT" -C "$ROOT" --transform 's,^,fieldkit/,' -T "$FILELIST" 2>/dev/null \
   || tar czf "$OUT" -C "$ROOT" -T "$FILELIST"; then
    sz="$(du -h "$OUT" 2>/dev/null | cut -f1)"
    echo "wrote $OUT ${sz:+($sz)}"
    if have sha256sum; then sha256sum "$OUT"; elif have shasum; then shasum -a 256 "$OUT"; fi
else
    echo "packaging FAILED" >&2; exit 1
fi

echo ""
echo "carry it over, then on the air-gapped box:"
echo "  tar xzf $(basename "$OUT") && cd fieldkit"
echo "  python3 -m pytest -q             # sanity: the engine runs (no tools needed)"
echo "  bin/fieldkit poc --check         # confirm the build toolchain is present"
echo "  bin/fieldkit init 'engagement'   # you're ready"
echo ""
echo "note: package.sh bundles source + PoCs, NOT the OS tools (nxc/impacket/certipy/"
echo "mingw/…). Install those on the attacker box while connected."
