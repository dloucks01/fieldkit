"""Shared config for the novelre kit — NOVEL vulnerability research on a binary/closed-source target,
standalone on a base Kali box. Generators PRINT commands (you run them); the kit does the deterministic
substrate (recon/disasm/fuzz/sanitize/symbolic/triage/exploit/variant), you supply the judgment.

HONEST CEILING (measured, 2024-26 SOTA): fuzzing + sanitizers find memory bugs; a crash != an exploit
(heap grooming/ASLR-leak/ROP stay expert-hard, <60% even for automated AEG); logic/auth bugs produce no
crash and are largely human territory; modern mitigations (CFI/CET/PAC) aren't beaten by automation.
Verify BY EFFECT — never claim a bug/exploit without a reproduced crash/control. Authorized targets only.
"""
LHOST, LPORT = "10.10.14.7", 443     # for a shellcode/revshell payload if you weaponize
ARCH = "amd64"                       # amd64 | i386 | arm | aarch64  (pwntools context)

# Dangerous sinks to hunt in a binary's imports/xrefs (classic memory-corruption + injection sources).
SINKS = {
    "memcpy":  "unbounded copy → stack/heap overflow (check the size arg)",
    "strcpy":  "no bound → overflow", "strcat": "no bound → overflow",
    "sprintf": "no bound → overflow", "vsprintf": "no bound → overflow",
    "gets":    "NEVER safe → overflow", "scanf": "%s no width → overflow",
    "read":    "size vs dest capacity", "recv": "size vs dest capacity",
    "printf":  "FORMAT STRING if arg is attacker-controlled (also fprintf/snprintf/syslog)",
    "system":  "command injection if arg tainted", "execve": "arg control → exec",
    "popen":   "command injection", "malloc": "size from input → heap primitive",
    "alloca":  "stack alloc from input → clash", "strncpy": "off-by-one / no NUL",
}

# Input vectors — where attacker data enters a binary (the fuzzing/taint entry points).
VECTORS = ["argv (command-line args)", "stdin", "a file it parses (-i/positional)",
           "a network socket (bind/recv)", "environment variables", "IPC / shared mem"]

def preflight_note():
    return ("# tools (base Kali has most): file readelf nm objdump strings gdb radare2 python3 pwntools "
            "ROPgadget ropper.  Install if missing: aflplusplus · ghidra · gdb-gef · valgrind · one_gadget "
            "· `pipx install angr`.  This kit prints installs and uses what's present.")
