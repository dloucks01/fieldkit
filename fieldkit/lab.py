"""The Defender lab harness — turn assume-caught red into lab-proven green.

``avcheck.sh`` measures the *static floor* (ClamAV) on the attacker box; it is a lower
bound and explicitly not a Defender verdict. This harness gets the real thing: it
drives a benign probe per technique against a **Defender-on lab host** and reads
Defender's *own* verdict (``Get-MpThreatDetection`` / ``Get-MpComputerStatus``), then
records green/red stamped with the signature version it was taken under.

Honesty is the whole point:

  * a **control** (the EICAR test file) runs first — if Defender does not remove it,
    real-time protection is off and *every* result this run would be meaningless, so
    the harness aborts rather than reporting false greens;
  * a technique is marked ``clean`` only when its probe actually ran (its marker came
    back) with no detection; blocked/absent marker is ``caught``;
  * techniques whose honest test needs a staged benign artifact are **skipped**, not
    faked — they stay red under assume-caught until you stage a probe.

The subprocess runner is injected, so the harness is testable against canned Defender
output without a lab.
"""
import re
from dataclasses import dataclass, field

from . import evasion
from .executor import Action, execute

#: The EICAR test string — the universal, benign AV control. Split so this source file
#: does not itself trip a scanner.
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

#: Read Defender's posture + any detection from the last two minutes, once per probe.
VERDICT_CMD = (
    "powershell -c \"Get-MpComputerStatus | fl RealTimeProtectionEnabled,AMSIEnabled,"
    "AntivirusSignatureVersion; Get-MpThreatDetection | "
    "? {$_.InitialDetectionTime -gt (Get-Date).AddMinutes(-2)} | fl ThreatID,Resources\"")


@dataclass(frozen=True)
class Probe:
    """A benign, self-contained test of one technique's detection surface."""

    technique: str
    command: str
    marker: str
    safety: str = "config-change"
    shell: str = "powershell"


def _marker(key):
    return f"FK-PROBE-{key}"


#: The control: drop EICAR and see whether Defender removes it (real-time proof).
CONTROL = Probe(
    technique="_control",
    command=("powershell -c \"$p=\\\"$env:TEMP\\fk.txt\\\"; Set-Content $p '" + EICAR + "'; "
             "Start-Sleep -Milliseconds 800; if (Test-Path $p) {'FK-EICAR-SURVIVED'} "
             "else {'FK-EICAR-REMOVED'}\""),
    marker="FK-EICAR",
    safety="config-change")

#: Self-contained probes. Techniques absent here need a staged benign artifact and are
#: reported as skipped — assume-caught keeps them red until one is staged.
PROBES = {
    # The AMSI surface: pass Microsoft's AMSI test sample through the script path.
    # Blocked = AMSI is guarding scripts (the un-bypassed script techniques are caught);
    # a returned marker means the bypass in the technique let it through.
    "ps-amsi-revshell": Probe(
        "ps-amsi-revshell",
        "powershell -c \"'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'; "
        "'" + _marker("ps-amsi-revshell") + "'\"",
        _marker("ps-amsi-revshell"), safety="read-only"),
    "inmem-fileless": Probe(
        "inmem-fileless",
        "powershell -c \"'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'; "
        "'" + _marker("inmem-fileless") + "'\"",
        _marker("inmem-fileless"), safety="read-only"),
    # Behavioural: create then immediately delete a throwaway local user (ASR/Defender
    # increasingly flag `net user`). Self-cleaning; also recorded as a cleanup artifact.
    "add-admin": Probe(
        "add-admin",
        "net user fkprobe P@ssw0rd!23 /add & net localgroup administrators fkprobe /add & "
        "net localgroup administrators fkprobe /del & net user fkprobe /del & "
        "echo " + _marker("add-admin"),
        _marker("add-admin"), safety="config-change", shell="cmd"),
}


# ---------------------------------------------------------------- interpretation

def parse_status(verdict_output):
    """(signature, rtp_on, has_recent_detection) from a Get-MpComputerStatus block."""
    text = verdict_output or ""
    sig = _field(text, "AntivirusSignatureVersion")
    rtp = _field(text, "RealTimeProtectionEnabled")
    rtp_on = None if rtp is None else rtp.strip().lower() == "true"
    has_detection = "ThreatID" in text and bool(_field(text, "ThreatID"))
    return sig, rtp_on, has_detection


def _field(text, name):
    m = re.search(rf"{re.escape(name)}\s*:\s*(\S+)", text)
    return m.group(1) if m else None


def interpret(probe_output, verdict_output, marker):
    """Verdict for one technique probe: ('clean'|'caught'|'error', signature, detail)."""
    sig, rtp_on, has_detection = parse_status(verdict_output)
    if rtp_on is False:
        return "error", sig, "real-time protection is off in the lab — verdict not trustworthy"
    ran = marker in (probe_output or "")
    if has_detection:
        return "caught", sig, "Defender logged a detection during the probe"
    if ran:
        return "clean", sig, "probe ran and its marker returned with no detection"
    return "caught", sig, "probe blocked — marker not returned (AMSI/Defender)"


def control_is_live(probe_output):
    """True when Defender removed the EICAR control (real-time protection proven on)."""
    out = probe_output or ""
    if "FK-EICAR-REMOVED" in out:
        return True
    return False


# ----------------------------------------------------------------------- harness

@dataclass
class LabReport:
    host: str = None
    aborted: str = None
    signature: str = None
    results: list = field(default_factory=list)   # (technique, verdict, detail)
    skipped: list = field(default_factory=list)   # techniques with no self-contained probe

    @property
    def green(self):
        return [t for t, v, _ in self.results if v == "clean"]


def _run_probe(store, host, cred, probe, run, allow, on_event):
    """Execute a probe + the verdict query; return (probe_output, verdict_output) or None
    if the executor blocked (gate / no transport)."""
    creates = ()
    if probe.technique == "add-admin":
        creates = [("lab probe user 'fkprobe' (self-deleted)", "net user fkprobe /del")]
    probe_res = execute(store, Action(
        host=host, cred=cred, command=probe.command, label=f"lab:{probe.technique}",
        safety=probe.safety, shell=probe.shell, creates=creates), run=run, allow=allow,
        on_event=on_event)
    if probe_res.blocked:
        return None, probe_res.blocked
    verdict_res = execute(store, Action(
        host=host, cred=cred, command=VERDICT_CMD, label=f"lab:{probe.technique}:verdict",
        safety="read-only", shell="powershell"), run=run, allow=allow)
    return probe_res.output, verdict_res.output


def run_tests(store, host, cred, *, techniques=None, run=None, on_event=None,
              allow=("read-only", "config-change")):
    """Prove techniques against the lab host. Returns a :class:`LabReport`.

    Runs the EICAR control first and aborts if the lab is not actually protecting, so
    a green can only ever come from a lab where Defender demonstrably reacts.
    """
    report = LabReport(host=host["ip"])

    ctrl_out, ctrl_err = _run_probe(store, host, cred, CONTROL, run, allow, on_event)
    if ctrl_out is None:
        report.aborted = f"control probe could not run: {ctrl_err}"
        return report
    if not control_is_live(ctrl_out):
        report.aborted = ("EICAR control survived — the lab's Defender is not removing a "
                          "known-bad file (real-time protection off?). Refusing to report "
                          "greens from an unprotected lab.")
        return report

    wanted = techniques or [t.key for t in evasion.for_os(evasion.WINDOWS)]
    for key in wanted:
        probe = PROBES.get(key)
        if probe is None:
            report.skipped.append(key)
            continue
        probe_out, verdict_out = _run_probe(store, host, cred, probe, run, allow, on_event)
        if probe_out is None:
            report.results.append((key, "error", verdict_out))  # blocked reason in verdict_out
            store.record_evasion(key, "error", detail=str(verdict_out))
            continue
        verdict, sig, detail = interpret(probe_out, verdict_out, probe.marker)
        report.signature = report.signature or sig
        report.results.append((key, verdict, detail))
        store.record_evasion(key, verdict, signature=sig, detail=detail)
        if on_event:
            on_event(f"  {key}: {verdict}" + (f" ({detail})" if verdict != "clean" else ""))
    return report
