#!/usr/bin/env python3
"""SYMBOLIC / CONCOLIC (angr) — solve the INPUT that reaches a target or crosses a gate the fuzzer stalls
on (magic bytes / checksum / password). Use SURGICALLY on a stuck frontier (path explosion kills whole-program
use). PRINTS an angr script. Usage:
  python3 gen_symbolic.py reach   --bin ./target --find 0x401337 [--avoid 0x401200]   # input that reaches an addr
  python3 gen_symbolic.py gate    --bin ./target --find 0x401337                       # get past one hard check
  python3 gen_symbolic.py control --bin ./target --input crash.bin                     # prove PC is attacker-controlled
"""
import sys
import _novelre_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg   = sys.argv[1] if len(sys.argv) > 1 else "reach"
b     = opt("--bin", "./target")
find  = opt("--find", "0x<target-addr>")
avoid = opt("--avoid")
inp   = opt("--input", "crash.bin")

print(f"# needs: angr (pipx install angr, or a venv — it's heavy). Target addr from gen_disasm (a sink/win/gate).")
print(f"# angr explores paths symbolically and SOLVES the input constraints — it finds bytes fuzzing couldn't guess.\n")

if arg in ("reach", "gate"):
    av = f"avoid={avoid}" if avoid else "avoid=()"
    print(f"cat > solve.py <<'EOF'")
    print(f"import angr, claripy")
    print(f"p = angr.Project({b!r}, auto_load_libs=False)")
    print(f"# feed symbolic input via stdin (or argv — see the commented variant):")
    print(f"st = p.factory.full_init_state(stdin=angr.SimFileStream(name='stdin', has_end=False))")
    print(f"sm = p.factory.simulation_manager(st)")
    print(f"sm.explore(find={find}, {av})")
    print(f"if sm.found:")
    print(f"    print(repr(sm.found[0].posix.dumps(0)))    # the stdin bytes that reach {find}")
    print(f"else: print('no path found — widen scope / add avoid addrs / check the target addr')")
    print(f"# argv variant: arg=claripy.BVS('a',8*64); st=p.factory.entry_state(args=[{b!r},arg]); ...; sm.found[0].solver.eval(arg,cast_to=bytes)")
    print(f"EOF")
    print(f"python3 solve.py")
    print(f"# -> ok: prints the concrete input that drives execution to {find} (e.g. the magic header/password).")
    print(f"#    feed that input to the real binary to confirm, or use it as a fuzzing seed to fuzz PAST the gate.")

elif arg == "control":
    print(f"# CONCOLIC controllability proof — is the crash's faulting register attacker-controlled? (crash != exploit)")
    print(f"cat > control.py <<'EOF'")
    print(f"import angr, claripy")
    print(f"p = angr.Project({b!r}, auto_load_libs=False)")
    print(f"data = open({inp!r},'rb').read()")
    print(f"sym = claripy.BVS('in', 8*len(data))")
    print(f"st = p.factory.full_init_state(stdin=sym)")
    print(f"sm = p.factory.simulation_manager(st, save_unconstrained=True)")
    print(f"sm.run()")
    print(f"if sm.unconstrained:")
    print(f"    s = sm.unconstrained[0]")
    print(f"    print('PC controllable:', s.solver.satisfiable(extra_constraints=[s.regs.pc == 0x4142434445464748]))")
    print(f"EOF")
    print(f"python3 control.py")
    print(f"# -> ok: 'PC controllable: True' = you control the instruction pointer = a control-hijack primitive (go to gen_exploit).")
    print(f"#    'False'/inconclusive = it's likely an OOB-read/info-leak or a non-controllable crash — triage in gen_crash.")
else:
    print("use: reach --find <addr> | gate --find <addr> | control --input <crash>"); sys.exit(1)

print(f"\n# angr too slow / path-explodes? Keep fuzzing with a DICTIONARY, or use it only from just-before the gate.")
