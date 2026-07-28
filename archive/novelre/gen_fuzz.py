#!/usr/bin/env python3
"""FUZZING — drive AFL++ (coverage-guided) at the binary to find crashes. Closed-source uses QEMU mode
(no recompile). PRINTS commands. Usage:
  python3 gen_fuzz.py afl     --bin ./target --input file|stdin|arg [--source /src]
  python3 gen_fuzz.py harness --bin ./target                  # persistent-mode / libFuzzer harness notes
  python3 gen_fuzz.py quick   --bin ./target                  # radamsa/honggfuzz dumb+fast alternatives
"""
import sys
import _novelre_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg   = sys.argv[1] if len(sys.argv) > 1 else "afl"
b     = opt("--bin", "./target")
inp   = opt("--input", "file")
src   = opt("--source")
AT    = "@@" if inp == "file" else ""     # AFL @@ = the input file path; empty = feed via stdin

if arg == "afl":
    print(f"# needs: aflplusplus (apt install aflplusplus). Input vector = {inp}.")
    print(f"# 0) SEED corpus is the #1 lever — real, valid, format-bearing inputs (a real file it parses):")
    print(f"mkdir -p in out; cp <a-few-real-valid-sample-inputs> in/    # <x> = you supply good seeds")
    if src:
        print(f"# 1a) SOURCE available -> compile with AFL instrumentation (fastest + coverage):")
        print(f"CC=afl-clang-fast CXX=afl-clang-fast++ make -C {src}   # or ./configure && make")
        print(f"afl-fuzz -i in -o out -- {b} {AT}")
    else:
        print(f"# 1b) CLOSED-SOURCE -> QEMU mode (-Q), no recompile needed (a bit slower):")
        print(f"afl-fuzz -Q -i in -o out -- {b} {AT}")
        print(f"#   faster alt for closed bins: FRIDA mode  -O  ;  or retrowrite/afl-dyninst to statically instrument.")
    print(f"#   stdin target? drop @@:  afl-fuzz -Q -i in -o out -- {b}")
    print(f"# 2) boost: a DICTIONARY of the format's magic tokens gets past parser gates:")
    print(f"afl-fuzz -Q -x /usr/share/afl/dictionaries/<fmt>.dict -i in -o out -- {b} {AT}")
    print(f"# -> ok: the AFL UI shows 'uniq crashes' climbing above 0; crashing inputs land in out/default/crashes/.")
    print(f"# -> then: triage each crash (gen_crash.py --input out/default/crashes/id..).  Stuck at a gate? gen_symbolic.py.")
    print(f"# SANITY: build a tiny known-crashing test first — AFL can silently miss crashes if the target swallows signals.")

elif arg == "harness":
    print(f"# needs: source (or a callable library fn). A HARNESS reaches deep code a CLI can't + fuzzes fast.")
    print(f"# libFuzzer/AFL persistent harness — call the parser directly on the fuzz input:")
    print(f"cat > harness.c <<'EOF'")
    print(f"#include <stdint.h>\n#include <stddef.h>")
    print(f"extern int target_parse(const uint8_t*, size_t);   // <x> = the function under test")
    print(f"int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){{ target_parse(d,n); return 0; }}")
    print(f"EOF")
    print(f"clang -g -fsanitize=address,fuzzer harness.c {src or '<src/obj>'} -o fuzz && ./fuzz -max_len=4096 in/")
    print(f"#   AFL++ persistent: afl-clang-fast + AFL_LOOP(1000) around the call = ~10-100x throughput.")
    print(f"# -> ok: coverage rises; a crash prints an ASan report with the exact bug class + stack. THIS is the OSS-Fuzz-Gen pattern.")
    print(f"# picking the target fn: from gen_disasm — the deepest input-reachable parser before the sink.")

elif arg == "quick":
    print(f"# no AFL / want a 5-minute smoke fuzz (dumb mutation — finds shallow bugs fast):")
    print(f"# radamsa (apt install radamsa):")
    print(f"while true; do radamsa in/* > t; {b} t 2>/dev/null || {{ cp t crash_$(date +%s); echo CRASH; }}; done")
    print(f"# honggfuzz (apt install honggfuzz) — coverage-guided, easy on closed bins:")
    print(f"honggfuzz -i in -- {b} ___FILE___")
    print(f"# -> ok: a saved crash_* / honggfuzz HONGGFUZZ.REPORT.TXT = a reproducible crashing input -> gen_crash.py.")
else:
    print("use: afl | harness | quick"); sys.exit(1)
