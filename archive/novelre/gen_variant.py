#!/usr/bin/env python3
"""VARIANT ANALYSIS — given one bug (or one dangerous pattern), systematically find ALL its SIBLINGS in the
binary. This is the single highest-yield technique in modern vuln research (Google Big Sleep found a real
0-day this way that fuzzing missed): a bug is rarely alone — the same mistake repeats. PRINTS commands.

Usage:
  python3 gen_variant.py sink   --bin ./target --sink strcpy      # every call-site of a sink, ranked by reachability
  python3 gen_variant.py clone  --bin ./target --func vuln_fn     # functions structurally similar to a known-buggy one
  python3 gen_variant.py diff   --old ./v1 --new ./v2            # a patch/CVE diff -> where else the fix was NOT applied
"""
import sys
import _novelre_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg  = sys.argv[1] if len(sys.argv) > 1 else "sink"
b    = opt("--bin", "./target")
sink = opt("--sink", "strcpy")
func = opt("--func", "vuln_fn")

if arg == "sink":
    print(f"# needs: radare2. You found (or suspect) a bug at ONE {sink} — enumerate EVERY {sink} site and vet each.")
    print(f"r2 -A -qc 'axt @ sym.imp.{sink}' {b}                # -> ok: every caller+addr of {sink}")
    print(f"# for EACH site, check the three things that make it a bug (decompile it — gen_disasm decompile --func <caller>):")
    print(f"#   1) is the SIZE/length arg attacker-controlled or unbounded?  2) is the DEST a fixed/small buffer?")
    print(f"#   3) is the site REACHABLE from an input vector (not dead/admin-only)?  all three -> a real variant.")
    print(f"# widen the net to sibling sinks (same bug class):")
    fam = {"strcpy": "strcpy strcat sprintf gets", "memcpy": "memcpy memmove bcopy",
           "printf": "printf fprintf sprintf snprintf syslog", "system": "system popen execl execve"}.get(sink, sink)
    print(f"for s in {fam}; do echo \"== $s ==\"; r2 -A -qc \"axt @ sym.imp.$s\" {b}; done")
    print(f"# -> ok: a ranked list of candidate siblings. THIS list is exactly the 'short grounded list' to hand a local model (if present) to triage.")

elif arg == "clone":
    print(f"# find functions STRUCTURALLY similar to a known-buggy one {func} (the bug pattern likely recurs):")
    print(f"# radare2 zignatures (function signatures) to match similar code:")
    print(f"r2 -A -qc 'zaf {func} sig; zg' {b} > sigs.z; r2 -A -qc 'z/ sigs.z' {b}   # match sig across the binary")
    print(f"# or diff-match with BinDiff/Diaphora against a reference; or grep the decompiled corpus for the same shape:")
    print(f"r2 -A -qc 'aflj' {b} | jq -r '.[].name' | while read f; do r2 -A -qc \"s $f; pdg\" {b} 2>/dev/null | "
          f"grep -l 'memcpy.*len' && echo $f; done   # crude: functions doing 'memcpy(...,...,len)'")
    print(f"# -> ok: a list of functions doing the same risky thing as {func} — vet each like a sink site.")

elif arg == "diff":
    old = opt("--old", "./v1"); new = opt("--new", "./v2")
    print(f"# PATCH/CVE variant analysis (Big Sleep's exact framing): a fix landed in ONE place — find where it did NOT.")
    print(f"# 1) diff the two versions to locate the fixed function(s):")
    print(f"radiff2 -AC {old} {new}                       # changed functions (needs radare2)")
    print(f"#   (better: BinDiff/Diaphora for a function-level matched diff.)")
    print(f"# 2) understand the FIX (what check/bound was added), then hunt the SAME pattern WITHOUT the fix elsewhere in {new}:")
    print(f"#   e.g. the fix added a length check before memcpy -> find other memcpy sites lacking that check (gen_variant sink).")
    print(f"# -> ok: an unpatched sibling of a known bug = a fresh candidate 0-day. Confirm by fuzz/reach, then gen_crash.")
else:
    print("use: sink --sink <s> | clone --func <f> | diff --old <a> --new <b>"); sys.exit(1)

print(f"\n# WHY THIS MATTERS: variant analysis is where a WEAK model (or a systematic human) most out-performs blind fuzzing —")
print(f"#   it reasons 'same mistake elsewhere' over a grounded candidate list, reaching bugs no fuzzer steers to.")
