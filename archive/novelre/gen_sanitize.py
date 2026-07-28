#!/usr/bin/env python3
"""SANITIZER MATRIX — turn a silent memory bug into a loud, classified crash. Different sanitizers catch
DISJOINT bug classes on the SAME input, so run the matrix. PRINTS commands. Usage:
  python3 gen_sanitize.py matrix --bin ./target [--source /src] [--input crash.bin]
"""
import sys
import _novelre_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

b   = opt("--bin", "./target")
src = opt("--source")
inp = opt("--input", "<crash-or-seed-input>")

print(f"# WHY: ASan alone is blind to uninitialized reads (MSan/Valgrind), integer/UB (UBSan), and races (TSan).")
print(f"# run the MATRIX on your crashing input (or over the fuzz corpus) to catch + classify everything.\n")

if src:
    print(f"# ===== SOURCE available ({src}) — rebuild with each sanitizer (highest fidelity) =====")
    print(f"# 1) ASan (heap/stack overflow, UAF, double-free) — table stakes:")
    print(f"make -C {src} CFLAGS='-g -fsanitize=address -fno-omit-frame-pointer'")
    print(f"{b} {inp}          # -> ok: 'AddressSanitizer: heap-buffer-overflow' + exact alloc/free stack + bug class")
    print(f"# 2) UBSan (signed/pointer overflow, OOB index, bad shift — the NON-crashing UB):")
    print(f"make -C {src} CFLAGS='-g -fsanitize=undefined -fno-sanitize-recover=all'")
    print(f"# 3) MSan (use of UNINITIALIZED memory — clang only, needs instrumented libs):")
    print(f"clang -g -fsanitize=memory -fsanitize-memory-track-origins {src}/*.c -o {b}.msan")
    print(f"# 4) TSan (data races, if multithreaded):  -fsanitize=thread")
    print(f"# -> each sanitizer that fires on the same input reports a DIFFERENT root cause. Record the class per finding.")
else:
    print(f"# ===== CLOSED-SOURCE (no rebuild) — instrument at runtime =====")
    print(f"# needs: valgrind (apt install valgrind). Catches uninit + OOB on stock binaries, no source:")
    print(f"valgrind --leak-check=full --track-origins=yes {b} {inp}")
    print(f"#   -> ok: 'Invalid write of size N' / 'Use of uninitialised value' + the faulting stack.")
    print(f"# QEMU + ASan-style checks: run under afl-qemu / retrowrite-instrumented, or use `qasan` (QEMU-AddressSanitizer).")
    print(f"# lighter: gdb with the heap-check + `gef`/`pwndbg` heap commands catches UAF/double-free interactively.")
    print(f"# NOTE: closed-source sanitizing is best-effort — Valgrind is the reliable no-rebuild win; prefer source if you can get it.")

print(f"\n# COMPLETENESS: note which sanitizers you ran — 'checked heap(ASan), uninit(Valgrind/MSan), UB(UBSan), races(TSan)'")
print(f"#   so a clean run is an HONEST 'no bug of these classes on this input', not a silent all-clear.")
print(f"# NEXT: a sanitizer crash is high-signal -> gen_crash.py to judge exploitability.")
