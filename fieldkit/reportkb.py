"""Remediation knowledge base — keyed by ``vector_type``.

The report and the recce bridge auto-fill severity, CWE, a standard description, and
(the part the customer needs) the REMEDIATION from here; state supplies the
target-specific bits (host, evidence, the exact captured steps). Every finding fieldkit
records carries a ``vector_type`` that is one of these keys — the privesc drivers set
it, so a stored finding renders and bridges without any hand mapping.

This is the v1 ``report/_report_kb.py`` ported into the package (Phase 3); it stays
stdlib-free so ``fieldkit`` runs standalone. Severities: Critical | High | Medium | Low | Info.
"""
KB = {
    # ---------------- Windows ----------------
    "unquoted_service": dict(sev="High", cwe="CWE-428", os="win",
        name="Unquoted service path leads to SYSTEM code execution",
        desc="A Windows service's ImagePath contains spaces and is not quoted, so the Service Control "
             "Manager attempts to execute intermediate paths (e.g. C:\\Program.exe) before the real binary. "
             "A low-privileged user who can write to an earlier path plants a binary that runs as the "
             "service account (typically SYSTEM).",
        rem="Quote the service ImagePath (`sc config <svc> binPath= \"\\\"C:\\Program Files\\...\\svc.exe\\\"\"`). "
            "Additionally, restrict write permissions on the parent directories so non-administrators cannot "
            "create files there. Audit all services with `wmic service get name,pathname` for unquoted paths."),
    "weak_service_perms": dict(sev="High", cwe="CWE-732", os="win",
        name="Weak service permissions allow reconfiguration to SYSTEM",
        desc="A low-privileged user holds SERVICE_CHANGE_CONFIG (or WRITE_DAC) on a service running as SYSTEM, "
             "allowing the binary path to be repointed to an attacker executable.",
        rem="Remove SERVICE_CHANGE_CONFIG / WRITE_DAC from non-administrative principals (review with "
            "`accesschk -uwcqv <user> *`). Restore the service DACL to the OS default."),
    "writable_service_binary": dict(sev="High", cwe="CWE-732", os="win",
        name="Writable service executable allows SYSTEM code execution",
        desc="The on-disk executable of a service running as SYSTEM is writable by a low-privileged user, who "
             "can overwrite it with an attacker binary.",
        rem="Set the service executable's ACL so only Administrators/SYSTEM can modify it. Install software into "
            "properly-ACL'd locations (Program Files), not user-writable directories."),
    "service_reg_imagepath": dict(sev="High", cwe="CWE-732", os="win",
        name="Writable service registry key allows SYSTEM code execution",
        desc="A low-privileged user can write the service's ImagePath value under "
             "HKLM\\System\\CurrentControlSet\\Services, repointing the binary even without SERVICE_CHANGE_CONFIG.",
        rem="Restore the default ACL on the service registry key so only Administrators/SYSTEM can write it."),
    "service_dll_hijack": dict(sev="High", cwe="CWE-427", os="win",
        name="DLL search-order hijack in a SYSTEM service",
        desc="A service running as SYSTEM loads a DLL by name from a directory that is writable by a "
             "low-privileged user or earlier in the search order than the legitimate DLL.",
        rem="Load DLLs by absolute path; enable SafeDllSearchMode and process-level mitigations "
            "(no user/remote directories in the search path); restrict ACLs on the affected directory."),
    "seimpersonate": dict(sev="High", cwe="CWE-250", os="win",
        name="SeImpersonatePrivilege abused to obtain SYSTEM (Potato)",
        desc="A service account holds SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege. A 'Potato'-class "
             "technique coerces a SYSTEM authentication and impersonates the resulting token to execute code "
             "as SYSTEM.",
        rem="Run services under least-privileged Virtual/Managed Service Accounts and remove SeImpersonate where "
            "not required. Keep the OS patched (RPC/EFSRPC/DCOM hardening). Monitor for named-pipe/token abuse."),
    "sebackup": dict(sev="High", cwe="CWE-250", os="win",
        name="SeBackup/Backup Operators enables credential hive theft",
        desc="Membership in Backup Operators (or SeBackupPrivilege/SeRestorePrivilege) lets a user read the "
             "protected SAM/SYSTEM/SECURITY registry hives and extract password hashes offline for "
             "pass-the-hash or cracking.",
        rem="Minimize Backup Operators membership; use dedicated least-privilege backup tooling; monitor and "
            "alert on registry hive save/copy operations."),
    "alwaysinstallelevated": dict(sev="High", cwe="CWE-269", os="win",
        name="AlwaysInstallElevated allows any user to install as SYSTEM",
        desc="Both the HKLM and HKCU AlwaysInstallElevated policy values are set to 1, so any user can execute "
             "an arbitrary MSI package with SYSTEM privileges.",
        rem="Set the AlwaysInstallElevated policy to Disabled (0) in both HKLM and HKCU via Group Policy "
            "(Computer/User Config > Administrative Templates > Windows Installer)."),
    "uac_bypass": dict(sev="Medium", cwe="CWE-269", os="win",
        name="UAC bypass elevates a filtered admin token to high integrity",
        desc="A user in the local Administrators group with a UAC-filtered (medium-integrity) token abuses an "
             "auto-elevating trusted binary to run code at high integrity without a UAC prompt.",
        rem="Set UAC to 'Always notify'; have administrators use separate non-privileged accounts for daily use; "
            "deploy application control (WDAC/AppLocker) to block the abused binaries' hijack paths."),
    "stored_creds": dict(sev="High", cwe="CWE-522", os="win",
        name="Reusable credentials stored in cleartext / recoverable form",
        desc="Credentials were recovered from unattend/sysprep files, the registry AutoLogon values, Credential "
             "Manager, saved sessions (PuTTY/WinSCP), or application config files, and reused to escalate.",
        rem="Remove plaintext credentials from files and the registry; clear AutoLogon; deploy LAPS for local "
            "admin passwords; rotate any exposed secrets."),
    "lsass": dict(sev="High", cwe="CWE-522", os="win",
        name="LSASS memory dump yields credentials",
        desc="LSASS process memory was dumped (e.g. via comsvcs.dll MiniDump) and parsed offline to recover "
             "NTLM hashes and/or Kerberos tickets.",
        rem="Enable LSASS as a protected process (RunAsPPL) and/or Credential Guard; restrict SeDebugPrivilege; "
            "deploy EDR to detect memory access to LSASS."),
    "gpp_cpassword": dict(sev="High", cwe="CWE-257", os="win", refs="CVE-2014-1812",
        name="Group Policy Preferences cpassword recoverable from SYSVOL",
        desc="A Group Policy Preferences XML in SYSVOL contains a cpassword value encrypted with a Microsoft-"
             "published AES key, readable and decryptable by any domain user.",
        rem="Remove all GPP items containing cpassword from SYSVOL; install MS14-025; use LAPS for managed "
            "local-admin passwords."),
    "printnightmare": dict(sev="Critical", cwe="CWE-269", os="win", refs="CVE-2021-34527",
        name="Print Spooler driver load executes code as SYSTEM (PrintNightmare)",
        desc="The Print Spooler service loads an attacker-supplied driver DLL and executes it as SYSTEM.",
        rem="Apply the current cumulative update; disable the Print Spooler service on systems that do not print; "
            "restrict Point-and-Print and driver installation to administrators."),
    "schtask_abuse": dict(sev="High", cwe="CWE-732", os="win",
        name="Writable scheduled task runs attacker code as SYSTEM",
        desc="A scheduled task configured to run as SYSTEM has an executable or task-definition XML writable by a "
             "low-privileged user.",
        rem="Restrict ACLs on task executables and the C:\\Windows\\System32\\Tasks store; run tasks under "
            "least-privileged principals."),
    "path_intercept_win": dict(sev="High", cwe="CWE-426", os="win",
        name="Writable PATH directory intercepts a SYSTEM service binary",
        desc="A SYSTEM service/task invokes a binary by relative name, and a directory writable by a low-"
             "privileged user precedes the legitimate location in the system PATH.",
        rem="Remove user-writable directories from the system PATH; invoke binaries by absolute path in "
            "services/tasks."),
    "localkernel_win": dict(sev="High", cwe="CWE-noinfo", os="win",
        name="Unpatched local kernel privilege-escalation vulnerability",
        desc="A missing OS patch left a local kernel/driver elevation-of-privilege vulnerability exploitable.",
        rem="Apply current security updates and establish a regular patch cycle with vulnerability scanning."),
    "seloaddriver": dict(sev="High", cwe="CWE-250", os="win",
        name="SeLoadDriverPrivilege abused to load a vulnerable driver (BYOVD)",
        desc="A user holding SeLoadDriverPrivilege loads a known-vulnerable signed kernel driver and exploits its "
             "arbitrary kernel read/write primitive to steal a SYSTEM token.",
        rem="Remove SeLoadDriverPrivilege from non-administrative accounts; enable Microsoft's vulnerable-driver "
            "blocklist (HVCI/Smart App Control); restrict driver loading."),
    "setakeownership": dict(sev="High", cwe="CWE-250", os="win",
        name="SeTakeOwnershipPrivilege abused to seize a SYSTEM-owned object",
        desc="A user holding SeTakeOwnershipPrivilege takes ownership of a file or registry key used by a SYSTEM "
             "process, rewrites its ACL, and replaces its contents to execute code as SYSTEM.",
        rem="Remove SeTakeOwnershipPrivilege from non-administrative accounts (User Rights Assignment)."),
    "semanagevolume": dict(sev="High", cwe="CWE-250", os="win",
        name="SeManageVolumePrivilege abused for arbitrary file write to SYSTEM",
        desc="SeManageVolumePrivilege is leveraged into an arbitrary-file-write primitive, used to plant a DLL "
             "loaded by a SYSTEM service and gain SYSTEM execution.",
        rem="Remove SeManageVolumePrivilege from non-administrative accounts; audit User Rights Assignment."),
    "hivenightmare": dict(sev="High", cwe="CWE-732", os="win", refs="CVE-2021-36934",
        name="User-readable SAM hive via shadow copy (HiveNightmare/SeriousSAM)",
        desc="Overly-permissive ACLs on the SAM/SYSTEM/SECURITY hives allow a low-privileged user to read them "
             "from a Volume Shadow Copy and extract local password hashes offline.",
        rem="Apply the vendor patch; restrict ACLs on %windir%\\System32\\config\\*; delete affected shadow "
            "copies (`vssadmin delete shadows`) after remediation."),
    "com_hijack": dict(sev="Medium", cwe="CWE-427", os="win",
        name="COM object hijack via per-user CLSID registration",
        desc="A privileged process instantiates a COM object whose per-user (HKCU) CLSID registration a low-"
             "privileged user can write, causing an attacker DLL to load in the privileged process.",
        rem="Prefer per-machine (HKLM) COM registrations; monitor HKCU\\Software\\Classes\\CLSID writes; "
            "application control to block untrusted DLLs."),
    "writable_run_key": dict(sev="Medium", cwe="CWE-732", os="win",
        name="Writable autorun (Run key/Startup) executes on higher-privileged logon",
        desc="A low-privileged user can write a machine autorun entry (Run key or Startup folder) whose command "
             "executes in the context of the next higher-privileged user to log on.",
        rem="Restrict write access to machine Run keys and the common Startup folder to administrators; monitor "
            "autorun changes."),
    "installed_software_weak_acl": dict(sev="High", cwe="CWE-732", os="win",
        name="Weak ACLs on installed software allow SYSTEM code execution",
        desc="A third-party application installed outside Program Files (or with misconfigured ACLs) has "
             "user-writable binaries/DLLs that run with SYSTEM/service privileges.",
        rem="Install software into properly-ACL'd locations; correct directory/file permissions so non-"
            "administrators cannot modify service or auto-run binaries."),
    "cmdline_creds": dict(sev="Medium", cwe="CWE-214", os="win",
        name="Credentials exposed on process command lines",
        desc="Credentials were observed passed as command-line arguments to processes (visible to any user via "
             "process listing) and reused to escalate.",
        rem="Never pass secrets as command-line arguments; use protected credential stores / managed identities; "
            "rotate exposed secrets."),
    # ---------------- Linux (additional) ----------------
    "readable_shadow": dict(sev="High", cwe="CWE-732", os="lin",
        name="Readable /etc/shadow enables offline password cracking",
        desc="A misconfiguration (or a capability such as cap_dac_read_search) makes /etc/shadow readable to a "
             "low-privileged user, whose password hashes can be cracked offline to recover root/other credentials.",
        rem="Restore /etc/shadow to 0640 root:shadow; remove the enabling capability/ACL; enforce strong password "
            "policy."),
    "private_key_exposure": dict(sev="High", cwe="CWE-522", os="lin",
        name="Exposed SSH private key permits access as another user",
        desc="A private SSH key readable by a low-privileged user allowed authentication as another user (often "
             "root or an administrator), escalating privileges.",
        rem="Restrict private keys to 0600 owner-only; remove keys from shared/readable locations; rotate exposed "
            "keys; passphrase-protect keys."),
    "ld_library_path": dict(sev="High", cwe="CWE-426", os="lin",
        name="Preserved LD_LIBRARY_PATH permits library injection to root",
        desc="A sudo rule preserves LD_LIBRARY_PATH (env_keep), letting a user point library resolution at a "
             "malicious shared object that loads as root.",
        rem="Remove LD_LIBRARY_PATH from sudo env_keep; rely on the default secure library search behavior."),
    "writable_ld_so_conf": dict(sev="High", cwe="CWE-426", os="lin",
        name="Writable ld.so.conf.d adds an attacker library path",
        desc="A low-privileged user can write /etc/ld.so.conf.d (or /etc/ld.so.conf), adding a directory of "
             "malicious libraries that get loaded by SUID/root binaries.",
        rem="Set /etc/ld.so.conf.d and /etc/ld.so.conf to root:root, non-writable by others; audit for injected "
            "entries and run `ldconfig`."),
    "disk_group": dict(sev="High", cwe="CWE-250", os="lin",
        name="Membership in the disk group grants raw filesystem access",
        desc="A user in the 'disk' group can read/write the raw block devices, bypassing filesystem permissions "
             "to read /etc/shadow or modify any file, which is equivalent to root.",
        rem="Remove non-administrative users from the 'disk' group; grant storage access via least-privileged, "
            "audited mechanisms."),
    "lxd_group": dict(sev="Critical", cwe="CWE-250", os="lin",
        name="Membership in the lxd group is root-equivalent",
        desc="A user in the 'lxd' group can launch a container that mounts the host filesystem and read/write any "
             "file as root, equivalent to unrestricted root.",
        rem="Remove non-administrative users from the 'lxd' group; restrict LXD access to administrators."),
    "at_job": dict(sev="High", cwe="CWE-732", os="lin",
        name="Writable at/batch job or spool executes as root",
        desc="An at/batch job (or its spool directory) writable by a low-privileged user executes commands as the "
             "root/owner when scheduled.",
        rem="Restrict the at spool and job files to root; limit at/batch use via at.allow/at.deny."),
    "cron_path_injection": dict(sev="High", cwe="CWE-426", os="lin",
        name="PATH injection in a root cron job",
        desc="A root cron job invokes a command by relative name while a directory writable by a low-privileged "
             "user precedes the real binary in the cron PATH, running attacker code as root.",
        rem="Set an explicit, absolute PATH in cron jobs; invoke commands by absolute path; remove user-writable "
            "directories from any privileged PATH."),
    "screen_root_session": dict(sev="High", cwe="CWE-732", os="lin",
        name="Attachable root screen/tmux session grants root shell",
        desc="A detached root GNU screen or tmux session with a world-accessible socket can be attached by a "
             "low-privileged user, yielding an interactive root shell.",
        rem="Restrict multiplexer sockets to the owner (0600); avoid running shared screen/tmux sessions as root."),
    # ---------------- Cross-platform ----------------
    "default_credentials": dict(sev="High", cwe="CWE-1392", os="",
        name="Default or vendor credentials in use",
        desc="A service or account retained default/vendor-shipped credentials, which were used to gain "
             "privileged access.",
        rem="Change all default credentials on deployment; enforce a credential-hardening baseline; disable unused "
            "default accounts."),
    "password_reuse": dict(sev="High", cwe="CWE-521", os="",
        name="Password reuse enables privilege escalation",
        desc="A credential recovered from one context was reused to authenticate to a higher-privileged account "
             "or service.",
        rem="Enforce unique passwords per account/tier; deploy a password manager / LAPS; monitor for credential "
            "reuse; require MFA for privileged access."),
    # ---------------- Initial access ----------------
    "exposed_service_cve": dict(sev="Critical", cwe="CWE-noinfo", os="",
        name="Exploitable known vulnerability in an internet/network-facing service",
        desc="A public-facing service was running a version with a known, exploitable vulnerability that granted "
             "code execution or authentication bypass, providing initial access.",
        rem="Patch the affected service to a fixed version; establish a vulnerability-management and patch cadence "
            "for all externally-reachable services; reduce the exposed attack surface."),
    "password_spray": dict(sev="High", cwe="CWE-307", os="",
        name="Weak/guessable credentials discovered via password spraying",
        desc="A valid account credential was obtained by spraying a common password across accounts on an exposed "
             "authentication service (SMB/RDP/OWA/VPN/SSH/etc.), yielding initial access.",
        rem="Enforce strong, unique passwords and MFA on all externally-reachable auth; configure account-lockout "
            "and spray-detection alerting; disable/rename default and stale accounts."),
    "anon_access": dict(sev="Medium", cwe="CWE-1188", os="",
        name="Anonymous / null-session access to a network service",
        desc="A service (SMB null session, anonymous FTP, unauthenticated LDAP/database/Redis) allowed access "
             "without credentials, exposing data or enumeration used to further the attack.",
        rem="Require authentication on all services; disable null sessions/anonymous access; restrict exposure to "
            "trusted networks."),
    "exposed_secret": dict(sev="High", cwe="CWE-552", os="",
        name="Exposed secret / sensitive file on a web or file service",
        desc="A sensitive artifact (exposed .git repo, .env, backup, config, or key) was reachable and contained "
             "credentials or information enabling access.",
        rem="Remove sensitive files from web roots and shares; rotate any exposed secrets; add access controls and "
            "scanning to prevent secret exposure."),
    "sqli": dict(sev="Critical", cwe="CWE-89", os="",
        name="SQL injection in a web application",
        desc="A web application parameter was vulnerable to SQL injection, allowing data extraction and — where the "
             "database supported it (e.g. MSSQL xp_cmdshell) — command execution on the host.",
        rem="Use parameterized queries/prepared statements throughout; apply least-privilege to the DB account; "
            "disable dangerous features (xp_cmdshell); add a WAF as defense-in-depth."),
    "webshell": dict(sev="Critical", cwe="CWE-434", os="",
        name="Arbitrary file upload leads to web-shell code execution",
        desc="A file-upload or write primitive allowed placing an executable script in the web root, yielding "
             "command execution as the web-server account.",
        rem="Validate upload type/content server-side (allowlist); store uploads outside the web root and serve "
            "non-executable; run the web server as a least-privileged account."),
    "rce_web": dict(sev="Critical", cwe="CWE-94", os="",
        name="Remote code execution in a web application",
        desc="A web application flaw (command injection, insecure deserialization, SSTI, or similar) allowed direct "
             "code execution on the server, providing initial access.",
        rem="Patch/refactor the vulnerable code; avoid passing user input to interpreters/deserializers; apply "
            "least privilege and input validation; keep frameworks current."),
    "asrep_roast": dict(sev="High", cwe="CWE-522", os="win",
        name="AS-REP roastable account yields a crackable credential",
        desc="A domain account had Kerberos pre-authentication disabled, letting any unauthenticated user request "
             "an AS-REP and crack the account's password offline.",
        rem="Enable Kerberos pre-authentication on all accounts; enforce strong passwords; monitor for AS-REP "
            "requests."),
    "unconstrained_delegation": dict(sev="Critical", cwe="CWE-266", os="win",
        name="Unconstrained Kerberos delegation permits full impersonation",
        desc="A computer or account is trusted for unconstrained delegation, so any authenticated "
             "principal (including a Domain Admin, or a DC coerced via PetitPotam/PrinterBug) that "
             "connects to it leaves a usable TGT in its memory — captured, this impersonates that "
             "principal domain-wide, typically yielding Domain Admin.",
        rem="Remove unconstrained delegation (set no TRUSTED_FOR_DELEGATION); use constrained or "
            "resource-based delegation instead; mark privileged accounts 'sensitive and cannot be "
            "delegated' / add them to Protected Users; patch the coercion vectors."),
    "constrained_delegation": dict(sev="High", cwe="CWE-266", os="win",
        name="Constrained delegation (S4U) allows service impersonation",
        desc="An account is configured for constrained delegation (msDS-AllowedToDelegateTo). Control of "
             "that account lets it use S4U2Self/S4U2Proxy to impersonate any user — including a Domain "
             "Admin — to the allowed service (and, via alternate SPNs, often others).",
        rem="Minimize delegation rights to the exact services required; prefer resource-based delegation "
            "scoped on the target; mark privileged accounts as non-delegatable (Protected Users)."),
    "rbcd": dict(sev="High", cwe="CWE-266", os="win",
        name="Resource-based constrained delegation write permits takeover",
        desc="A principal can write msDS-AllowedToActOnBehalfOfOtherIdentity on a target computer, letting "
             "an attacker-controlled account impersonate any user (e.g. a Domain Admin) to that host via "
             "S4U — full compromise of the target.",
        rem="Restrict write access to computer objects' msDS-AllowedToActOnBehalfOfOtherIdentity; audit who "
            "holds GenericWrite/GenericAll over computers; remove stale delegation entries."),
    "kerberoast": dict(sev="High", cwe="CWE-522", os="win",
        name="Kerberoastable service account yields a crackable credential",
        desc="A domain account with a Service Principal Name (SPN) is requestable by any authenticated user; the "
             "returned service ticket is encrypted with the account's password hash, allowing an offline crack. "
             "Service accounts are frequently over-privileged and their passwords rarely rotate.",
        rem="Use group Managed Service Accounts (gMSA) or machine accounts for services; where a user SPN is "
            "unavoidable, enforce a long (25+ char) random password; remove unused SPNs; monitor for anomalous "
            "TGS-REQ volume (event 4769)."),
    "path_traversal": dict(sev="High", cwe="CWE-22", os="",
        name="Path traversal / local file inclusion",
        desc="A file/path parameter was not validated, allowing traversal outside the intended directory to read "
             "arbitrary files (credentials, config, keys) — and, via inclusion, code execution.",
        rem="Canonicalize and validate file paths against an allowlist; reject traversal sequences; run with "
            "least privilege; disable dangerous include wrappers (allow_url_include)."),
    "ssti": dict(sev="Critical", cwe="CWE-1336", os="",
        name="Server-side template injection",
        desc="User input was rendered as a template expression, allowing execution of template-engine primitives "
             "and, ultimately, arbitrary code on the server.",
        rem="Never render user input as a template; use logic-less templates or strict sandboxing; pass user data "
            "only as bound variables."),
    "command_injection": dict(sev="Critical", cwe="CWE-78", os="",
        name="OS command injection",
        desc="User input was passed into an operating-system command, allowing arbitrary command execution on the "
             "host.",
        rem="Avoid shelling out; use language APIs with argument arrays (no shell); strictly validate/allowlist "
            "input; run with least privilege."),
    "deserialization": dict(sev="Critical", cwe="CWE-502", os="",
        name="Insecure deserialization",
        desc="The application deserialized attacker-controlled data, allowing a gadget/POP chain to execute code "
             "on the server.",
        rem="Do not deserialize untrusted data; use safe formats (JSON with schema); sign/validate serialized "
            "data; keep libraries patched and remove known gadget dependencies."),
    "ssrf": dict(sev="High", cwe="CWE-918", os="",
        name="Server-side request forgery",
        desc="The application fetched a URL controllable by the attacker, allowing access to internal services and "
             "cloud metadata (credential theft) and, via protocol smuggling, code execution.",
        rem="Allowlist outbound destinations; block link-local/internal ranges and non-HTTP schemes; require IMDSv2/"
            "metadata protections; validate and canonicalize URLs."),
    "xxe": dict(sev="High", cwe="CWE-611", os="",
        name="XML external entity injection",
        desc="An XML parser processed external entities from attacker input, allowing arbitrary file read, SSRF, "
             "and out-of-band data exfiltration.",
        rem="Disable external entity and DTD processing in all XML parsers; use hardened parser configurations; "
            "prefer non-XML formats where possible."),
    # ---------------- AD / network initial access (SOTA) ----------------
    "llmnr_poisoning": dict(sev="High", cwe="CWE-300", os="win",
        name="LLMNR/NBT-NS/mDNS poisoning captures network credentials",
        desc="Broadcast name-resolution (LLMNR/NBT-NS/mDNS) allowed an attacker on the local network to spoof "
             "responses and capture NetNTLMv2 authentication material, then crack or relay it.",
        rem="Disable LLMNR (GPO: 'Turn off multicast name resolution'), NBT-NS, and mDNS; enforce SMB signing; "
            "segment networks and use network access control."),
    "ntlm_relay": dict(sev="Critical", cwe="CWE-294", os="win",
        name="NTLM relay to a privileged service",
        desc="Captured/coerced NTLM authentication was relayed to a service that did not enforce signing/channel "
             "binding (LDAP/SMB/ADCS), granting access up to full domain compromise.",
        rem="Enforce SMB signing and LDAP signing + channel binding (EPA); enable Extended Protection on ADCS web "
            "enrollment (or disable it); patch coercion vectors (PetitPotam/PrinterBug/DFSCoerce); restrict NTLM."),
    "adcs_esc": dict(sev="Critical", cwe="CWE-295", os="win",
        name="Active Directory Certificate Services misconfiguration (ESC)",
        desc="A vulnerable certificate template or CA configuration allowed a low-privileged user to obtain a "
             "certificate authenticating as a privileged account (often Domain Admin); certificate auth persists "
             "across password resets.",
        rem="Remediate the specific ESC (remove enrollee-supplied-SAN/EDITF_ATTRIBUTESUBJECTALTNAME2, fix template "
            "ACLs and EKUs, enable manager approval); enable Extended Protection; audit + monitor certificate issuance."),
    "cloud_password_spray": dict(sev="High", cwe="CWE-307", os="",
        name="Cloud identity password spray / weak MFA",
        desc="A valid cloud identity (M365/Entra/Okta) credential was obtained by password spraying an exposed "
             "auth endpoint, and MFA was not enforced (or legacy auth bypassed it), granting access.",
        rem="Enforce phishing-resistant MFA via Conditional Access for ALL users and apps; block legacy "
            "authentication; enable smart lockout and sign-in risk policies; alert on spray patterns."),
    # ---------------- Modern web (SOTA) ----------------
    "jwt": dict(sev="High", cwe="CWE-347", os="",
        name="JSON Web Token signature/validation weakness",
        desc="A JWT was accepted with a forged or unverified signature (alg:none, a crackable HMAC secret, kid "
             "injection, or RS256→HS256 confusion), letting the attacker forge arbitrary claims (e.g. admin).",
        rem="Pin the expected algorithm server-side; use strong secrets/asymmetric keys; validate kid against an "
            "allowlist; verify iss/aud/exp; never accept alg:none."),
    "request_smuggling": dict(sev="High", cwe="CWE-444", os="",
        name="HTTP request smuggling (desync)",
        desc="Front-end and back-end disagreed on request boundaries (CL/TE), allowing a smuggled request that "
             "bypassed front-end access controls, captured other users' requests, or poisoned the cache.",
        rem="Normalize/reject ambiguous Content-Length/Transfer-Encoding; use HTTP/2 end-to-end; make front-end "
            "and back-end parsing consistent; drop connections on ambiguity."),
    "idor": dict(sev="High", cwe="CWE-639", os="",
        name="Insecure direct object reference / broken object-level authorization",
        desc="The application returned or modified objects based on a client-supplied identifier without checking "
             "the requester's authorization, exposing or altering other users' data.",
        rem="Enforce per-object authorization on every request server-side; use unpredictable identifiers as "
            "defense-in-depth; add access-control tests to CI."),
    "mass_assignment": dict(sev="High", cwe="CWE-915", os="",
        name="Mass assignment / excessive data binding",
        desc="The API bound client-supplied fields directly to internal objects, letting the attacker set "
             "privileged attributes (role/isAdmin/verified) they should not control.",
        rem="Bind only an explicit allowlist of fields (DTOs); never auto-bind privileged attributes; validate "
            "server-side."),
    "unauth_database": dict(sev="High", cwe="CWE-306", os="",
        name="Unauthenticated database / data service access",
        desc="A database or data service (MongoDB/Elasticsearch/CouchDB/Memcached/Redis/etc.) was exposed without "
             "authentication, disclosing data and credentials and — for some engines (Redis/CouchDB/MySQL/Postgres) "
             "— allowing code execution on the host.",
        rem="Require authentication and bind services to internal interfaces only; enforce network segmentation/"
            "firewalling; disable dangerous features; patch known RCE CVEs."),
    # ---------------- Novel binary / memory-safety (novelre) ----------------
    "memory_corruption": dict(sev="Critical", cwe="CWE-787", os="",
        name="Memory-corruption vulnerability (buffer overflow / OOB write)",
        desc="Attacker-controlled input reaches a memory operation without adequate bounds checking, corrupting "
             "memory (stack/heap out-of-bounds write) and enabling control-flow hijack or arbitrary code execution.",
        rem="Fix the bounds check / use memory-safe APIs (bounded copies); enable and keep all mitigations "
            "(ASLR/PIE, NX/DEP, stack canaries, Full RELRO, CFI/CET); fuzz + sanitize in CI; consider a memory-safe "
            "language for the affected component."),
    "use_after_free": dict(sev="Critical", cwe="CWE-416", os="",
        name="Use-after-free",
        desc="The program used a heap object after it was freed, allowing an attacker who controls the reallocated "
             "memory to corrupt state and gain code execution.",
        rem="Null out pointers after free; use smart pointers / RAII; enable ASan in test/CI; adopt hardened "
            "allocators; consider a memory-safe language."),
    "format_string": dict(sev="High", cwe="CWE-134", os="",
        name="Format-string vulnerability",
        desc="Attacker-controlled data was used as a printf-family format string, allowing memory read/write and "
             "potentially code execution.",
        rem="Never pass user input as a format string — use a fixed format (`printf(\"%s\", user)`); enable "
            "-Wformat-security and treat its warnings as errors."),
    "exposed_docker_api": dict(sev="Critical", cwe="CWE-306", os="",
        name="Exposed Docker/container management API",
        desc="The Docker daemon API (or a Kubernetes kubelet/API) was reachable without authentication, allowing "
             "an attacker to run a container that mounts the host filesystem — equivalent to root on the host.",
        rem="Never expose the Docker socket/API over the network unauthenticated; require TLS client certs; enable "
            "kubelet/API authn+authz (disable anonymous-auth); restrict with network policy."),
    "prototype_pollution": dict(sev="High", cwe="CWE-1321", os="",
        name="Prototype pollution",
        desc="Attacker-controlled keys (__proto__/constructor) were merged into objects, polluting the prototype "
             "and enabling privilege bypass, denial of service, or — via a gadget — remote code execution.",
        rem="Reject __proto__/constructor/prototype keys; use Map or null-prototype objects; freeze prototypes; "
            "keep libraries patched."),
    # ---------------- Linux ----------------
    "gtfobins_suid": dict(sev="High", cwe="CWE-732", os="lin",
        name="SUID-root binary permits a shell escape to root",
        desc="A binary owned by root with the SUID bit set exposes functionality (shell-out, file read/write) "
             "that a low-privileged user leverages to execute commands as root.",
        rem="Remove the SUID bit where not strictly required (`chmod u-s`); where the functionality is needed, "
            "replace with a narrowly-scoped sudo rule or Linux capabilities and validate against GTFOBins."),
    "gtfobins_sudo": dict(sev="High", cwe="CWE-250", os="lin",
        name="Overly-permissive sudo rule permits a shell escape to root",
        desc="A sudoers rule permits a low-privileged user to run a binary that can spawn a shell or read/write "
             "arbitrary files, yielding full root.",
        rem="Tighten the sudoers entry: restrict to exact arguments, use NOEXEC, avoid shell-capable binaries, "
            "and remove NOPASSWD. Cross-check every allowed binary against GTFOBins."),
    "sudo_misconfig": dict(sev="High", cwe="CWE-269", os="lin",
        name="Sudo configuration weakness enables root escalation",
        desc="A sudo misconfiguration (preserved LD_PRELOAD/LD_LIBRARY_PATH via env_keep, a sudoedit rule on a "
             "vulnerable sudo version, or a Runas spec bypass) allows escalation to root.",
        rem="Remove LD_* from env_keep; keep sudo patched (>=1.9.x); correct Runas_Spec entries; set a hardened "
            "secure_path."),
    "capability": dict(sev="High", cwe="CWE-250", os="lin",
        name="Dangerous file capability grants root-equivalent access",
        desc="A file capability (e.g. cap_setuid, cap_dac_read_search, cap_sys_admin, cap_sys_module) on a "
             "binary lets a low-privileged user gain root or read/modify arbitrary system state.",
        rem="Remove the capability where unneeded (`setcap -r <file>`); grant the minimum capability required and "
            "only on tightly-controlled binaries."),
    "kernel_cve": dict(sev="High", cwe="CWE-noinfo", os="lin",
        name="Unpatched local kernel privilege-escalation vulnerability",
        desc="A missing kernel patch left a local elevation-of-privilege vulnerability exploitable to root.",
        rem="Patch the kernel to a fixed version and establish a regular update cycle. Where feasible, disable "
            "unprivileged user namespaces (`sysctl kernel.unprivileged_userns_clone=0`) to reduce exposure."),
    "writable_cron": dict(sev="High", cwe="CWE-732", os="lin",
        name="Root cron job executes a user-writable script",
        desc="A cron job running as root executes a script (or a script in a directory) writable by a low-"
             "privileged user, who appends commands that run as root.",
        rem="Set the script and its directory to be writable only by root (0755 root:root); run cron jobs under "
            "the least-privileged account necessary."),
    "wildcard": dict(sev="High", cwe="CWE-88", os="lin",
        name="Wildcard argument injection in a root-run command",
        desc="A privileged script runs a command with a shell wildcard (e.g. `tar/chown/rsync *`) in a directory "
             "a user can write, allowing attacker-named files to be interpreted as command options.",
        rem="Avoid wildcards in privileged scripts; use `--` and absolute paths; restrict write access to the "
            "working directory."),
    "path_hijack": dict(sev="High", cwe="CWE-426", os="lin",
        name="PATH hijack of a relative command in a root context",
        desc="A SUID binary or sudo rule invokes a command by relative name; a user places a malicious binary of "
             "that name earlier in PATH, which then executes as root.",
        rem="Invoke commands by absolute path; set a trusted `secure_path` in sudoers; avoid relative execution "
            "in SUID programs."),
    "ld_preload": dict(sev="High", cwe="CWE-426", os="lin",
        name="LD_PRELOAD / ld.so.preload injection yields root",
        desc="A preserved LD_PRELOAD/LD_LIBRARY_PATH (via sudo env_keep) or a writable /etc/ld.so.preload lets a "
             "user load a shared object whose constructor runs as root.",
        rem="Remove LD_PRELOAD/LD_LIBRARY_PATH from sudo env_keep; ensure /etc/ld.so.preload is root-owned and "
            "0644 (or absent)."),
    "nfs_no_root_squash": dict(sev="High", cwe="CWE-282", os="lin",
        name="NFS export with no_root_squash enables SUID root drop",
        desc="An NFS share exported with no_root_squash trusts the client's root identity, allowing an attacker "
             "who is root on a client to place a SUID-root binary that executes as root on the server.",
        rem="Export shares with root_squash (the default); restrict exports to specific hosts; avoid no_root_squash."),
    "writable_motd": dict(sev="High", cwe="CWE-732", os="lin",
        name="Writable /etc/update-motd.d script runs as root on login",
        desc="A script under /etc/update-motd.d is writable by a low-privileged user and is executed as root by "
             "pam_motd on interactive login.",
        rem="Set /etc/update-motd.d scripts to be writable only by root (0755 root:root)."),
    "writable_sudoers": dict(sev="Critical", cwe="CWE-732", os="lin",
        name="Writable /etc/sudoers.d grants arbitrary root",
        desc="The /etc/sudoers.d directory (or a file within it) is writable by a low-privileged user, who drops "
             "a NOPASSWD rule granting full root.",
        rem="Set /etc/sudoers.d and its files to root:root 0440; audit for unexpected drop-in files."),
    "python_hijack": dict(sev="High", cwe="CWE-427", os="lin",
        name="Python module hijack in a root-run script",
        desc="A script executed as root imports a module resolvable from a directory the attacker can write (or "
             "via a preserved PYTHONPATH), executing attacker code as root on import.",
        rem="Restrict the script directory to root; remove PYTHONPATH from sudo env_keep; pin absolute/venv "
            "imports for privileged scripts."),
    "writable_systemd": dict(sev="High", cwe="CWE-732", os="lin",
        name="Writable systemd unit runs ExecStart as root",
        desc="A systemd .service/.timer unit (or its directory) is writable by a low-privileged user, whose "
             "ExecStart command runs as root when the unit starts.",
        rem="Set unit files and their directories to root:root 0644/0755; audit /etc/systemd/system for user-"
            "writable units."),
    "docker_group": dict(sev="Critical", cwe="CWE-250", os="lin",
        name="Membership in docker/lxd group is root-equivalent",
        desc="A user in the docker (or lxd) group can mount the host filesystem into a container and read/write "
             "any file as root, which is equivalent to unrestricted root.",
        rem="Remove non-administrative users from the docker/lxd groups; use rootless containers (podman/rootless "
            "Docker); restrict access to the container socket."),
    "world_writable_sensitive": dict(sev="Critical", cwe="CWE-732", os="lin",
        name="World/user-writable security-critical file",
        desc="A security-critical file (e.g. /etc/passwd or /etc/shadow) is writable by a low-privileged user, "
             "who edits it to obtain a UID-0 account.",
        rem="Restore correct ownership/permissions (/etc/passwd 0644 root:root, /etc/shadow 0640 root:shadow, "
            "/etc/sudoers 0440 root:root)."),
}

DEFAULT = dict(sev="Medium", cwe="CWE-269", os="",
    name="Local privilege escalation", desc="A local privilege-escalation vector was identified.",
    rem="Apply least-privilege configuration and current patches; see the referenced technique.")

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

def entry(vt):
    return KB.get(vt, DEFAULT)

# =====================================================================================================
# OPERATIONAL RISK of EXPLOITING each vector on a live (possibly production) target — drives the
# "prove-without-breaking" guidance and the internal cleanup manifest. Labels, safest -> most dangerous:
#   read-only | reversible | service-restart | config-edit | crash-risk
# =====================================================================================================
RISK = {
    # read-only (safest — reading/exfil, no state change)
    "lsass": "read-only", "stored_creds": "read-only", "gpp_cpassword": "read-only", "sebackup": "read-only",
    "hivenightmare": "read-only", "readable_shadow": "read-only", "private_key_exposure": "read-only",
    "cmdline_creds": "read-only", "default_credentials": "read-only", "password_reuse": "read-only",
    # reversible (shell-spawn / minor artifact, easily undone)
    "gtfobins_suid": "reversible", "gtfobins_sudo": "reversible", "sudo_misconfig": "reversible",
    "capability": "reversible", "docker_group": "reversible", "lxd_group": "reversible", "disk_group": "reversible",
    "screen_root_session": "reversible", "uac_bypass": "reversible", "seimpersonate": "reversible",
    "setakeownership": "reversible", "semanagevolume": "reversible", "com_hijack": "reversible",
    "writable_run_key": "reversible", "path_hijack": "reversible", "cron_path_injection": "reversible",
    "path_intercept_win": "reversible", "python_hijack": "reversible", "ld_library_path": "reversible",
    # service-restart (may disrupt a running/production service)
    "weak_service_perms": "service-restart", "writable_service_binary": "service-restart",
    "service_reg_imagepath": "service-restart", "installed_software_weak_acl": "service-restart",
    "schtask_abuse": "service-restart", "writable_systemd": "service-restart", "writable_cron": "service-restart",
    "unquoted_service": "service-restart", "service_dll_hijack": "service-restart", "at_job": "service-restart",
    "writable_motd": "service-restart", "wildcard": "service-restart", "printnightmare": "service-restart",
    "nfs_no_root_squash": "reversible",
    # config-edit (touches auth/loader files — higher blast radius)
    "world_writable_sensitive": "config-edit", "writable_sudoers": "config-edit", "ld_preload": "config-edit",
    "writable_ld_so_conf": "config-edit", "alwaysinstallelevated": "config-edit",
    # crash-risk (kernel/driver — can panic/BSOD)
    "kernel_cve": "crash-risk", "localkernel_win": "crash-risk", "seloaddriver": "crash-risk",
    # initial access
    "exposed_service_cve": "crash-risk",          # exploiting a live service can crash it
    "password_spray": "reversible",               # no target change, BUT lockout/DoS risk — see the finding
    "anon_access": "read-only", "exposed_secret": "read-only", "asrep_roast": "read-only",
    "kerberoast": "read-only",
    "unconstrained_delegation": "reversible", "constrained_delegation": "reversible",
    "rbcd": "config-edit",
    "sqli": "reversible", "webshell": "reversible", "rce_web": "reversible",
    "path_traversal": "read-only", "ssti": "reversible", "command_injection": "reversible",
    "deserialization": "reversible", "ssrf": "read-only", "xxe": "read-only",
    # SOTA initial access + modern web
    "llmnr_poisoning": "reversible", "ntlm_relay": "config-edit", "adcs_esc": "config-edit",
    "cloud_password_spray": "reversible", "jwt": "read-only", "request_smuggling": "reversible",
    "idor": "read-only", "mass_assignment": "config-edit", "prototype_pollution": "reversible",
    "unauth_database": "read-only", "exposed_docker_api": "reversible",
    "memory_corruption": "crash-risk", "use_after_free": "crash-risk", "format_string": "reversible",
}
RISK_META = {
    "read-only": dict(danger="Low — reading data only, no change to the target.",
        safe_proof="Reading/exfiltrating the data IS the proof; no modification of the target is required.",
        cleanup="Securely delete any exfiltrated copies (hives, memory dumps, keys, credential files) from the "
                "target and from your staging directory."),
    "reversible": dict(danger="Low — spawns a shell or leaves a minor artifact; easily undone.",
        safe_proof="Spawn the shell (or trigger once) to confirm, then exit. Do NOT create a persistent backdoor "
                   "account unless the rules of engagement require demonstrating persistence.",
        cleanup="Remove any planted script/binary/registry key; delete any account created; the shell itself "
                "leaves no persistent change."),
    "service-restart": dict(danger="MEDIUM — may disrupt a running (possibly production) service on restart.",
        safe_proof="Prove you CAN modify the target (icacls / `ls -l` / a write test) WITHOUT actually replacing "
                   "the live binary or restarting a production service. Where uptime matters, confirm the finding "
                   "by writability, not by detonation.",
        cleanup="Restore the original binary/config/registry value from your backup and return the service to its "
                "prior state; remove any planted files."),
    "config-edit": dict(danger="MEDIUM/HIGH — edits system auth/loader files; a mistake can lock out users or "
                                "break binaries.",
        safe_proof="Demonstrate write access with a benign marker you immediately remove, rather than appending a "
                   "working backdoor rule. Always back up the file before any edit.",
        cleanup="Revert the edited file to its exact original content (restore from backup); remove any added "
                "lines, rules, or accounts."),
    "crash-risk": dict(danger="HIGH — kernel/driver exploit; can PANIC / BSOD the host.",
        safe_proof="Do NOT detonate on production without a snapshot and explicit sign-off. Where possible, "
                   "evidence applicability by precise version-match (`uname -r` / systeminfo vs the CVE) instead "
                   "of running the exploit.",
        cleanup="If detonated: verify host stability. A one-shot LPE usually leaves no persistent artifact, but "
                "confirm no dropped files or accounts remain."),
}
def risk_of(vt):   return RISK.get(vt, "reversible")
def risk_meta(vt): return RISK_META[risk_of(vt)]
