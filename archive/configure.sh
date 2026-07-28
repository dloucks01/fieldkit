#!/bin/sh
# ===================================================================================================
# ONE-SHOT CONFIG — set LHOST / LPORT (+ optional DOMAIN) across EVERY module at once, so you never
# edit the _*_common.py files by hand (and never send a revshell to the wrong host).
#
# Usage:   sh configure.sh <LHOST> [LPORT] [DOMAIN]
# Example: sh configure.sh 10.10.14.7 443 corp.local
# ===================================================================================================
LHOST="$1"; LPORT="${2:-443}"; DOM="$3"
ROOT=$(cd "$(dirname "$0")" && pwd)
# find at ANY depth (get-in configs live under access/network, access/web, access/services)
CONFIGS=$(find "$ROOT" -name '_*_common.py' | sort)
[ -z "$LHOST" ] && { echo "usage: sh configure.sh <LHOST> [LPORT=443] [DOMAIN]"; echo "current:"; echo "$CONFIGS" | xargs grep -H '^LHOST' 2>/dev/null | sed "s#$ROOT/##"; exit 1; }

n=0
for f in $CONFIGS; do
    [ -f "$f" ] || continue
    # replace only the VALUE, keep any trailing comment on the line
    sed -i -E "s|^(LHOST, LPORT = )\"[^\"]*\", *[0-9]+|\1\"$LHOST\", $LPORT|" "$f"
    [ -n "$DOM" ] && sed -i -E "s|^(DOMAIN[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"$DOM\"|" "$f"
    n=$((n + 1))
done
echo "set  LHOST=$LHOST  LPORT=$LPORT  ${DOM:+DOMAIN=$DOM}  across $n module config files:"
echo "$CONFIGS" | xargs grep -H '^LHOST' | sed "s#$ROOT/##"
echo ""
echo "Note: winpriv also has TOOL / STAGE / REVTYPE, and access/network + access/web have TURL/USERLIST/PASSLIST —"
echo "  set those per-engagement in the module's _*_common.py (they're target-specific, not global)."
