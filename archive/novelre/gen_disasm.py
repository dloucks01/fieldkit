#!/usr/bin/env python3
"""STATIC RE — disassemble/decompile a binary, find the dangerous SINKS, and xref them back to input.
The binary analog of source taint: which sink does attacker data reach? PRINTS commands (radare2/Ghidra).

Usage:
  python3 gen_disasm.py map       --bin ./target                 # find every call-site of a dangerous sink
  python3 gen_disasm.py decompile --bin ./target --func main     # decompile a function (r2ghidra / Ghidra)
  python3 gen_disasm.py path      --bin ./target --sink strcpy   # trace input -> sink (call graph)
"""
import sys
import _novelre_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg  = sys.argv[1] if len(sys.argv) > 1 else "map"
b    = opt("--bin", "./target")
func = opt("--func", "main")
sink = opt("--sink", "strcpy")
sinks = "|".join(P.SINKS)

if arg == "map":
    print(f"# needs: radare2 (base Kali). Finds who CALLS each dangerous sink = your candidate bug sites.")
    print(f"# analyze + list every cross-ref to an imported sink:")
    print(f"r2 -A -qc 'afl~+{sink}' {b}                      # is the sink present as a function/import?")
    for s in list(P.SINKS)[:6]:
        print(f"r2 -A -qc 'axt @ sym.imp.{s}' {b}                # -> ok: prints each CALL site of {s} (addr + caller fn)")
    print(f"# one-liner across ALL sinks:")
    print(f"for s in {' '.join(list(P.SINKS)[:8])}; do echo \"== $s ==\"; r2 -A -qc \"axt @ sym.imp.$s\" {b}; done")
    print(f"# -> ok: each hit = (caller function, address). Decompile the caller (below) to see if the size/arg is attacker-controlled.")
    print(f"# rizin users: swap `r2`->`rizin`.  no radare2? objdump -d -M intel {b} | grep -B20 'call.*{sink}'")

elif arg == "decompile":
    print(f"# needs: r2ghidra plugin (r2pm -ci r2ghidra) OR Ghidra installed. Read the sink's caller as C.")
    print(f"# radare2 + Ghidra decompiler (fast):")
    print(f"r2 -A -qc 's {func}; pdg' {b}                    # pdg = decompile {func} to C  (pdc = r2's own)")
    print(f"#   -> ok: you get C-ish pseudocode; read the buffer sizes + where the arg to the sink comes from.")
    print(f"# full Ghidra headless (better decompiler, no GUI):")
    print(f"analyzeHeadless /tmp ghp -import {b} -postScript <(echo 'from ghidra.app.decompiler import DecompInterface') -deleteProject 2>/dev/null")
    print(f"#   practical: just open {b} in Ghidra GUI, navigate to {func}, read the Decompile pane.")
    print(f"# gdb disassembly of one function:  gdb -batch -ex 'disassemble {func}' {b}")

elif arg == "path":
    print(f"# needs: radare2. Trace how attacker input reaches {sink} (the 'is it reachable' question).")
    print(f"# 1) find the sink's callers, then walk UP the call graph toward an input vector (main/recv/read):")
    print(f"r2 -A -qc 'axt @ sym.imp.{sink}' {b}             # direct callers")
    print(f"r2 -A -qc 'agc @ main' {b}                       # call graph from main — does a path reach the caller?")
    print(f"r2 -A -qc 'agCd' {b} > callgraph.dot; xdot callgraph.dot   # whole-program call graph (visual)")
    print(f"# 2) confirm the arg to {sink} is derived from input (argv/read/recv), not a constant -> decompile the caller.")
    print(f"# -> ok: an input-vector -> ... -> {sink} path with an attacker-sized/controlled arg = a real candidate bug.")
    print(f"#    then: fuzz it (gen_fuzz.py) to get a crash, or prove reachability with angr (gen_symbolic.py reach).")
else:
    print("use: map | decompile --func <f> | path --sink <s>"); sys.exit(1)

print(f"\n# NEXT: a candidate sink -> fuzz for a crash (gen_fuzz) · find ALL its siblings (gen_variant --sink {sink}).")
