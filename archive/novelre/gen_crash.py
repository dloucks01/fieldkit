#!/usr/bin/env python3
"""CRASH TRIAGE — is this crash EXPLOITABLE? Classify the fault (PC control / write-what-where vs OOB-read),
dedup a pile of crashes, and minimize the input. PRINTS commands (gdb/pwntools). Usage:
  python3 gen_crash.py triage   --bin ./target --input crash.bin
  python3 gen_crash.py dedup    --bin ./target --dir out/default/crashes
  python3 gen_crash.py minimize --bin ./target --input crash.bin
"""
import sys
import _novelre_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "triage"
b   = opt("--bin", "./target")
inp = opt("--input", "crash.bin")
d   = opt("--dir", "out/default/crashes")

if arg == "triage":
    print(f"# needs: gdb (+ gef/pwndbg for the exploitability verdict — apt install gdb; gef: bit.ly/gef).")
    print(f"# 1) reproduce + capture the fault facts:")
    print(f"gdb -batch -ex 'run < {inp}' -ex 'info registers' -ex 'bt' -ex 'x/i $pc' {b}   # stdin target")
    print(f"#   file-arg target:  gdb -batch -ex 'run {inp}' -ex 'info registers' -ex bt {b}")
    print(f"#   -> ok: you see SIGSEGV + the faulting instruction and register state.")
    print(f"# 2) the exploitability question — read the fault:")
    print(f"#   $pc == 0x4141414141414141 (your input bytes) -> YOU CONTROL PC = control-hijack (HIGH/exploitable)")
    print(f"#   faulting insn WRITES to a controlled addr (mov [rax],rbx; rax=input) -> write-what-where (HIGH)")
    print(f"#   faulting insn READS a controlled addr -> OOB-read / info-leak (MEDIUM — good for an ASLR leak)")
    print(f"#   crash in free()/malloc() -> heap corruption (tcache/fastbin — HIGH but grooming-hard)")
    print(f"# 3) let a tool classify it (gef 'exploitable' / CASR):")
    print(f"gdb -q -ex 'run < {inp}' -ex 'exploitable' -ex quit {b}      # gef/pwndbg-style verdict")
    print(f"casr-gdb -o {inp}.casr -- {b} {inp} 2>/dev/null; cat {inp}.casr   # CASR severity, if installed")
    print(f"# -> record: bug class + is-PC-controlled. PROVE controllability with gen_symbolic.py control.")

elif arg == "dedup":
    print(f"# many crashes -> group by CRASH SITE (backtrace) so you triage each UNIQUE bug once, not 500 dupes:")
    print(f"# needs: gdb. Hash the top of the backtrace per crash:")
    print(f"for c in {d}/*; do sig=$(gdb -batch -ex 'run < '$c -ex 'bt 3' {b} 2>/dev/null | grep '#' | md5sum | cut -c1-8); "
          f"echo \"$sig  $c\"; done | sort | awk '!seen[$1]++'")
    print(f"# -> ok: one representative crash per unique site. AFL++ also has: afl-cmin -i {d} -o unique -- {b} @@")

elif arg == "minimize":
    print(f"# shrink the crashing input to the essential bytes (easier to understand + build the exploit):")
    print(f"afl-tmin -i {inp} -o {inp}.min -- {b} @@        # needs aflplusplus; @@ = file arg (drop for stdin)")
    print(f"#   -> ok: {inp}.min still crashes but is much smaller.  Find the overflow offset in it:")
    print(f"python3 -c \"from pwn import *; print(cyclic(200))\" > pat; {b} pat   # then in gdb: cyclic_find(\\$pc)")
    print(f"# -> the offset = distance to the return address / controlled register (feeds gen_exploit.py --offset).")
else:
    print("use: triage --input <c> | dedup --dir <d> | minimize --input <c>"); sys.exit(1)
