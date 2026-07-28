#!/usr/bin/env python3
"""BINARY INTAKE -> attack surface: format/arch, MITIGATIONS, dangerous imports, input vectors, interesting
strings/symbols. The first thing you run — it tells you what you're up against + where to fuzz/hunt.
PRINTS commands. Usage:  python3 gen_triage.py --bin ./target [--source /path/src]"""
import sys
import _novelre_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

b   = opt("--bin", "./target")
src = opt("--source")

print(P.preflight_note() + "\n")
print(f"# ===== 1) WHAT IS IT — format / arch / linkage =====")
print(f"file {b}                                  # ELF/PE, 32/64, arch, static/dynamic, stripped?")
print(f"#   -> ok: e.g. 'ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped'")
print(f"readelf -h {b}; readelf -d {b} | grep NEEDED   # entry point + shared-lib deps\n")

print(f"# ===== 2) MITIGATIONS — decide the exploit path up front =====")
print(f"checksec --file={b}                       # (or pwn checksec {b})")
print(f"#   NX on  -> no shellcode on stack, need ROP/ret2libc")
print(f"#   PIE on -> need an address leak first (ASLR)")
print(f"#   Canary -> need a leak or an overflow that skips it")
print(f"#   RELRO full -> no GOT overwrite;  Fortify -> _chk wrappers on the sinks")
print(f"#   -> this set decides gen_exploit's strategy — write it down.\n")

print(f"# ===== 3) DANGEROUS IMPORTS — the sink shortlist =====")
sinks = "|".join(P.SINKS)
print(f"nm -D {b} 2>/dev/null | grep -iE '({sinks})'    # dynamic-symbol imports")
print(f"objdump -T {b} 2>/dev/null | grep -iE '({sinks})'")
print(f"rabin2 -i {b} | grep -iE '({sinks})'          # radare2's import list")
print(f"#   each import present = a candidate sink; xref it to input in gen_disasm. Meaning:")
for fn, why in list(P.SINKS.items())[:8]:
    print(f"#     {fn:<9}{why}")
print(f"#     ...(full list in _novelre_common.SINKS)\n")

print(f"# ===== 4) INPUT VECTORS — where attacker data enters (= the fuzz/taint entry) =====")
for v in P.VECTORS:
    print(f"#   - {v}")
print(f"ltrace -f {b} <sample-input> 2>&1 | head -40   # watch which libc calls fire on input (dynamic peek)")
print(f"strace -f {b} <sample-input> 2>&1 | grep -iE 'open|read|recv|execve' | head   # syscalls: files/sockets it touches\n")

print(f"# ===== 5) LOW-HANGING INTEL — strings / symbols =====")
print(f"strings -n 6 {b} | grep -iE 'passw|key|/bin/|http|%s|format|version|debug' | head -30")
print(f"rabin2 -zz {b} | head        # all strings incl. embedded;  nm {b} | grep ' T '  = defined functions")
print(f"# firmware/blob? binwalk -e {b}   (extract filesystem) — then triage the binaries inside.\n")

if src:
    print(f"# ===== SOURCE available ({src}) — you can also do source-level static + sanitizer builds =====")
    print(f"grep -rInE '\\b({sinks})\\s*\\(' {src} | head -30      # sink call-sites in source")
    print(f"#   -> rebuild with sanitizers (gen_sanitize.py) + source-fuzz a harness (gen_fuzz.py). Much higher signal.")

print(f"# ===== NEXT =====")
print(f"#   map input -> a sink:  gen_disasm.py --bin {b}")
print(f"#   just fuzz it:         gen_fuzz.py --bin {b}")
print(f"#   found a bug-shape?    gen_variant.py --bin {b}   (find its siblings)")
