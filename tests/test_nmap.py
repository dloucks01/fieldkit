#!/usr/bin/env python3
"""Nmap XML ingest — parse an nmap -oX file into hosts + services.

Pinned:

  * pure ``parse(text) -> NmapIntent`` — no store, no I/O
  * ``apply(store, intent)`` folds into state in one transaction, respects scope
  * down hosts drop; closed/filtered ports drop; only up + open lands
  * OS is coarse-labeled (windows / linux / None) from the top osmatch
  * hostname preserved when present, absent when not
  * idempotent — re-ingesting doesn't duplicate hosts or services
  * malformed XML returns an empty intent, not a raise
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import nmap  # noqa: E402
from fieldkit.state import Store  # noqa: E402


BASIC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.0.0/28" version="7.94">
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="app01" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/></port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx" version="1.24"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/></port>
      <port protocol="tcp" portid="443"><state state="filtered"/></port>
    </ports>
    <os><osmatch name="Linux 5.15" accuracy="98"/></os>
  </host>
  <host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/>
    <hostnames><hostname name="ws02" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/>
        <service name="microsoft-ds"/></port>
    </ports>
    <os><osmatch name="Microsoft Windows 10" accuracy="99"/></os>
  </host>
</nmaprun>
"""


class ParseTest(unittest.TestCase):
    def test_up_hosts_land_down_hosts_drop(self):
        intent = nmap.parse(BASIC_XML)
        ips = [h.ip for h in intent.hosts]
        self.assertEqual(ips, ["10.0.0.5", "10.0.0.7"])         # 10.0.0.6 is down

    def test_open_ports_land_closed_and_filtered_drop(self):
        intent = nmap.parse(BASIC_XML)
        app01 = [h for h in intent.hosts if h.ip == "10.0.0.5"][0]
        ports = [s.port for s in app01.services]
        self.assertEqual(sorted(ports), [22, 80])                # 8080 closed, 443 filtered
        self.assertNotIn(8080, ports)
        self.assertNotIn(443, ports)

    def test_service_metadata_captured(self):
        intent = nmap.parse(BASIC_XML)
        app01 = [h for h in intent.hosts if h.ip == "10.0.0.5"][0]
        ssh = [s for s in app01.services if s.port == 22][0]
        self.assertEqual(ssh.product, "OpenSSH")
        self.assertEqual(ssh.version, "8.9p1")

    def test_hostnames_and_coarse_os(self):
        intent = nmap.parse(BASIC_XML)
        by_ip = {h.ip: h for h in intent.hosts}
        self.assertEqual(by_ip["10.0.0.5"].hostname, "app01")
        self.assertEqual(by_ip["10.0.0.5"].os, "linux")
        self.assertEqual(by_ip["10.0.0.7"].hostname, "ws02")
        self.assertEqual(by_ip["10.0.0.7"].os, "windows")

    def test_scanner_metadata(self):
        intent = nmap.parse(BASIC_XML)
        self.assertIn("nmap", (intent.scanner or "").lower())
        self.assertIn("7.94", intent.scanner or "")
        self.assertIn("10.0.0.0/28", intent.args or "")

    def test_malformed_xml_returns_empty_intent(self):
        # broken XML → empty intent, not an exception
        intent = nmap.parse("<not valid xml")
        self.assertEqual(intent.hosts, [])

    def test_non_nmap_xml_returns_empty_intent(self):
        # valid XML that isn't nmap → skip cleanly
        intent = nmap.parse("<?xml version='1.0'?><rss><item/></rss>")
        self.assertEqual(intent.hosts, [])

    def test_ipv4_only_ipv6_falls_through(self):
        xml = ('<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94">'
               '<host><status state="up"/>'
               '<address addr="fe80::1" addrtype="ipv6"/>'
               '<ports></ports></host></nmaprun>')
        intent = nmap.parse(xml)
        self.assertEqual(intent.hosts, [])                       # ipv6-only hosts skip


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")

    def test_end_to_end_hosts_and_services_persist(self):
        rep = nmap.apply(self.store, nmap.parse(BASIC_XML))
        self.assertEqual(rep.hosts_added, 2)
        self.assertEqual(rep.services_added, 3)   # 22, 80 on .5 + 445 on .7
        self.assertIsNotNone(self.store.host_by_ip("10.0.0.5"))
        self.assertEqual(self.store.host_by_ip("10.0.0.5")["hostname"], "app01")
        self.assertEqual(self.store.host_by_ip("10.0.0.5")["os"], "linux")
        # services reachable via state
        services = self.store.services(self.store.host_by_ip("10.0.0.5")["id"])
        self.assertEqual(sorted(s["port"] for s in services), [22, 80])

    def test_idempotent_second_apply_enriches_not_duplicates(self):
        nmap.apply(self.store, nmap.parse(BASIC_XML))
        rep2 = nmap.apply(self.store, nmap.parse(BASIC_XML))
        self.assertEqual(rep2.hosts_added, 0)
        self.assertEqual(rep2.hosts_enriched, 2)
        self.assertEqual(rep2.services_added, 0)
        self.assertEqual(rep2.services_enriched, 3)
        # total counts unchanged
        self.assertEqual(self.store.counts()["hosts"], 2)

    def test_scope_rules_drop_out_of_scope_hosts(self):
        self.store.scope_add("10.0.0.5/32", kind="allow")   # only .5 allowed
        rep = nmap.apply(self.store, nmap.parse(BASIC_XML))
        self.assertEqual(rep.hosts_added, 1)                    # only 10.0.0.5 landed
        self.assertEqual(rep.out_of_scope, ["10.0.0.7"])
        self.assertIsNone(self.store.host_by_ip("10.0.0.7"))

    def test_service_enrichment_never_overwrites_with_none(self):
        # first scan: version-less port scan
        xml_v1 = ('<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94">'
                  '<host><status state="up"/>'
                  '<address addr="10.0.0.5" addrtype="ipv4"/>'
                  '<ports><port protocol="tcp" portid="22">'
                  '<state state="open"/></port></ports></host></nmaprun>')
        nmap.apply(self.store, nmap.parse(xml_v1))
        # second scan: -sV adds version
        nmap.apply(self.store, nmap.parse(BASIC_XML))
        svc = self.store.services(self.store.host_by_ip("10.0.0.5")["id"])
        ssh = [s for s in svc if s["port"] == 22][0]
        self.assertEqual(ssh["product"], "OpenSSH")             # enriched, not overwritten
        self.assertEqual(ssh["version"], "8.9p1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
