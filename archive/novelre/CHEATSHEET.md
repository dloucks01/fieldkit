# novelre — novel vulnerability research on a binary (standalone, base Kali)

**Find a previously-unknown bug in a custom/closed-source binary and build a working exploit.** This is real
vuln research, not orchestration of known exploits. Generators run on YOUR box and *print* commands driving
Kali RE tools; **you supply the judgment** (a field kit has no LLM — if you run a local model, the structured
outputs below are the "short grounded list" it triages). **Authorized targets only.**

**Reading the steps:** `<x>` = you supply · `needs:` = precondition · `-> ok:` = what confirms it worked.

## Honest ceiling (measured — 2024-26 SOTA)
- Fuzzing + sanitizers find **memory bugs**; a **crash ≠ an exploit** — heap grooming / ASLR-leaks / ROP stay expert-hard (even automated AEG is <60% on curated pwn).
- **Logic/auth bugs produce no crash** → invisible to fuzzers, largely human territory.
- Modern mitigations (**CFI / CET shadow-stack / PAC**) aren't beaten by automation.
- **Verify BY EFFECT** — never claim a bug/exploit without a reproduced crash/control. (This is the one rule that separates real findings from LLM "slop.")
This kit makes an expert *much* faster and more systematic; it does not autonomously discover 0-days on a laptop.

## The funnel
```
gen_triage   → what is it: format/arch, MITIGATIONS (decide the exploit path), dangerous imports, input vectors
gen_disasm   → static RE: decompile + find the dangerous SINKS + xref input→sink   (which sink does input reach?)
gen_fuzz     → AFL++ (QEMU mode for closed-source) → CRASHES        ← the discovery workhorse
gen_symbolic → angr: cross a gate fuzzing stalls on / prove PC control   (surgical)
gen_sanitize → Valgrind / ASan matrix → turn a silent bug into a classified crash
gen_crash    → triage: is it EXPLOITABLE? (PC control / write-what-where) · dedup · minimize
gen_exploit  → weaponize, MITIGATION-AWARE: shellcode / ret2libc / ROP / fmtstr / one_gadget / heap
gen_variant  → find ALL siblings of the bug (Big Sleep's highest-yield move)
```

## Walkthrough
```bash
# 0) tools:  see preflight below. Kali has r2/gdb/pwntools/ROPgadget; install aflplusplus/angr/valgrind/ghidra if missing.
python3 gen_triage.py  --bin ./target                      # mitigations + sink shortlist + where input enters
python3 gen_disasm.py  map --bin ./target                  # every dangerous sink call-site
python3 gen_disasm.py  path --bin ./target --sink strcpy   # does input reach it?
mkdir in; cp <real-sample-inputs> in/                       # SEED corpus = the #1 fuzzing lever
python3 gen_fuzz.py    afl --bin ./target --input file      # AFL++ QEMU mode → crashes
python3 gen_symbolic.py gate --bin ./target --find <addr>  # stuck at a magic-byte/checksum gate? solve it
python3 gen_sanitize.py matrix --bin ./target --input crash.bin   # classify the crash (ASan/Valgrind/UBSan/MSan)
python3 gen_crash.py   triage --bin ./target --input crash.bin    # exploitable? find the offset
python3 gen_exploit.py skeleton --bin ./target             # pwntools scaffold; then rop/ret2libc/fmtstr per mitigations
python3 gen_variant.py sink --bin ./target --sink strcpy   # find the bug's siblings — the real yield
```

## Preflight (base Kali)
Present on Kali: `file readelf nm objdump strings gdb radare2 python3 pwntools ROPgadget ropper binwalk`.
Install if missing (the generators print these): `apt install aflplusplus valgrind honggfuzz radamsa ghidra` ·
`pipx install angr` · `one_gadget` (gem) · gef/pwndbg for gdb. The kit uses what's present and degrades gracefully.

## Handoff
A working exploit / confirmed bug → write it up in **`../report/`** (`gen_report.py`) with the PoC command trail;
vector types: `memory_corruption` / `command_injection` / `format_string` / etc. Minimize the PoC, record the
crashing input as evidence, and note the exact bug class + mitigation context.

## Where a local model helps (optional)
If you run gpt-oss/ollama on the box, feed it the **grounded lists** this kit produces — the `gen_disasm` sink
list, the `gen_variant` candidates, the `gen_crash` fault facts — and have it hypothesize/triage. That's the
SOTA hybrid (deterministic substrate + narrow model judgment, verified by effect). Nothing here *requires* it.
