"""Evasion as a ranking axis — the technique catalog and the assume-caught model.

The design's stance: **Defender is on, and every evasion technique is caught until a
lab proves otherwise.** This module encodes that. It catalogs the delivery techniques
the kit actually uses — the v1 loader variants (native XOR'd PE on disk, in-memory
reflective/fileless managed loads, an AMSI-patched PowerShell revshell, ``nc``,
``add_admin``, an MSI) — with the properties that decide detection risk: does it
present an **AMSI surface** (managed/script content Defender scans), does it need an
AMSI bypass, does it clear the **static floor** (an XOR'd native PE does; msfvenom
does not), does it need egress.

A technique's *live* status is not in this file — it comes from lab evidence in state
(:mod:`fieldkit.lab`). Here we resolve that evidence against the assume-caught rule:
no fresh lab result means **red**, always. :func:`recommend` then orders delivery so
a lab-proven-green path is preferred, and among untested paths the quiet native
no-AMSI ones float above a loud ``add_admin`` or an AMSI-scanned script.
"""
from dataclasses import dataclass
from datetime import datetime, timezone

WINDOWS, LINUX = "windows", "linux"

#: A lab-green result older than this is treated as stale — signatures move, and a
#: month-old "clean" is not evidence Defender will miss it today.
STALE_DAYS = 14

# verdicts a technique can hold, worst to best for ranking.
UNTESTED, CAUGHT, STALE, GREEN = "untested", "caught", "stale", "green"


@dataclass(frozen=True)
class Technique:
    """One delivery/evasion technique and the properties that set its detection risk."""

    key: str
    title: str
    os: str
    delivery: str            # native-pe-ondisk | in-memory | script | lolbin | installer
    amsi_surface: bool       # presents managed/script content AMSI scans
    needs_amsi_bypass: bool
    static_floor: str        # clean (XOR'd native clears ClamAV) | flagged | na
    egress: bool             # needs network egress to work
    stealth: int             # inherent quietness, higher = quieter (ties among untested)
    note: str = ""


#: The catalog. Windows first (where AMSI/Defender live); a couple of Linux entries so
#: posture spans the whole kit. Append a row to add a technique.
TECHNIQUES = (
    Technique("native-exe", "native XOR'd EXE on disk", WINDOWS, "native-pe-ondisk",
              amsi_surface=False, needs_amsi_bypass=False, static_floor="clean",
              egress=False, stealth=8,
              note="a native PE is not AMSI-scanned; the XOR'd payload clears the static floor. "
                   "The load/spawn behaviour is still visible to EDR."),
    Technique("native-dll", "native XOR'd DLL hijack", WINDOWS, "native-pe-ondisk",
              amsi_surface=False, needs_amsi_bypass=False, static_floor="clean",
              egress=False, stealth=8,
              note="search-order / service DLL hijack; same AMSI-free, static-clean profile as the exe."),
    Technique("nc-revshell", "nc.exe reverse shell", WINDOWS, "native-pe-ondisk",
              amsi_surface=False, needs_amsi_bypass=False, static_floor="clean",
              egress=True, stealth=6,
              note="no PowerShell, so AMSI/CLM-safe; nc.exe itself is a well-known signature — stage a clean build."),
    Technique("inmem-fileless", "fileless in-memory .NET load", WINDOWS, "in-memory",
              amsi_surface=True, needs_amsi_bypass=True, static_floor="na",
              egress=False, stealth=5,
              note="base64 -> Assembly.Load, never touches disk; the loader is managed, so it needs the AMSI byte-patch."),
    Technique("inmem-reflective", "HTTP reflective .NET load", WINDOWS, "in-memory",
              amsi_surface=True, needs_amsi_bypass=True, static_floor="na",
              egress=True, stealth=4,
              note="downloads + reflects the assembly in memory; managed loader + egress both add surface."),
    Technique("ps-amsi-revshell", "AMSI-patched PowerShell revshell", WINDOWS, "script",
              amsi_surface=True, needs_amsi_bypass=True, static_floor="na",
              egress=True, stealth=3,
              note="script content is the most AMSI-exposed path; the self-patch is itself increasingly signatured."),
    Technique("msi-aie", "MSI via AlwaysInstallElevated", WINDOWS, "installer",
              amsi_surface=False, needs_amsi_bypass=False, static_floor="flagged",
              egress=False, stealth=2,
              note="installers are heavily inspected; the msfvenom MSI flags on the static floor — use a clean wixl build."),
    Technique("add-admin", "add a local admin (net user)", WINDOWS, "lolbin",
              amsi_surface=False, needs_amsi_bypass=False, static_floor="na",
              egress=False, stealth=1,
              note="no AMSI at all, but it creates an account — a 4720 event and a permanent artifact. Loud."),
    Technique("ld-preload", "LD_PRELOAD .so", LINUX, "native-pe-ondisk",
              amsi_surface=False, needs_amsi_bypass=False, static_floor="clean",
              egress=False, stealth=7,
              note="Linux has no AMSI; host AV is rare. The XOR'd/compiled .so clears the ClamAV floor."),
    Technique("kernel-poc", "drop + run a kernel PoC", LINUX, "native-pe-ondisk",
              amsi_surface=False, needs_amsi_bypass=False, static_floor="clean",
              egress=False, stealth=4,
              note="a wrong-build kernel PoC can panic the box — this is crash-risk, not just detection-risk."),
)

_BY_KEY = {t.key: t for t in TECHNIQUES}


def by_key(key):
    return _BY_KEY.get(key)


def for_os(os_name):
    return [t for t in TECHNIQUES if t.os == os_name]


@dataclass(frozen=True)
class Status:
    """A technique resolved against lab evidence and the assume-caught rule."""

    technique: object
    verdict: str                 # untested | caught | stale | green
    signature: str = None        # the Defender signature version the result was taken under
    tested_at: str = None
    reason: str = ""

    @property
    def usable(self):
        """Only a fresh green is evidence you may rely on it — everything else is red."""
        return self.verdict == GREEN


def _age_days(tested_at, now):
    try:
        then = datetime.fromisoformat(tested_at)
    except (TypeError, ValueError):
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (now - then).total_seconds() / 86400.0


def resolve(technique, record, *, now=None, stale_days=STALE_DAYS):
    """Resolve a technique's status from its latest lab ``record`` (a row/dict with
    ``verdict``/``signature``/``tested_at``), or ``None`` if never tested.

    Assume-caught is total: no record → untested (red); a ``caught`` record → caught;
    a ``clean`` record only counts as green while it is fresh, else stale (red).
    """
    if record is None:
        return Status(technique, UNTESTED, reason="never lab-tested — assumed caught")
    verdict = record["verdict"] if hasattr(record, "keys") else record.get("verdict")
    sig = (record["signature"] if hasattr(record, "keys") else record.get("signature"))
    tested = (record["tested_at"] if hasattr(record, "keys") else record.get("tested_at"))
    if verdict == "caught":
        return Status(technique, CAUGHT, sig, tested, "Defender flagged it in the lab")
    if verdict == "clean":
        now = now or datetime.now(timezone.utc)
        age = _age_days(tested, now)
        if age is not None and age > stale_days:
            return Status(technique, STALE, sig, tested,
                          f"clean {int(age)}d ago — older than {stale_days}d, re-test")
        return Status(technique, GREEN, sig, tested, "lab-proven clean against current signatures")
    return Status(technique, UNTESTED, sig, tested, "no usable verdict on record")


#: verdict -> ranking weight (higher first). green wins; untested beats a known catch.
_VERDICT_RANK = {GREEN: 3, UNTESTED: 1, STALE: 1, CAUGHT: 0}


def recommend(statuses):
    """Order techniques best-first for delivery.

    A fresh green outranks everything. Among the rest (all effectively red under
    assume-caught) the quiet native no-AMSI paths come before AMSI-scanned scripts and
    the loud ``add_admin``/installer — the design's "prefer native paths with no AMSI
    surface" made concrete. A known catch sinks to the bottom.
    """
    def key(s):
        t = s.technique
        return (-_VERDICT_RANK.get(s.verdict, 1),
                t.amsi_surface,           # no-AMSI first
                -t.stealth,
                t.key)
    return sorted(statuses, key=key)


def posture(result_for, os_name, *, now=None):
    """Project lab/live evidence into what the escalation loop needs to walk deliveries.

    ``result_for(key)`` returns the stored evasion record for a technique (or ``None``);
    it is injected so this stays store-free. Returns ``(order, caught)``:

      * ``order`` — technique keys best-first (:func:`recommend`), so the loop re-delivers
        a caught vector via the next-preferred method;
      * ``caught`` — the set of techniques with a live/lab **caught** verdict, which the
        loop skips without firing (assume-caught: never re-burn a known-caught delivery).

    Only a genuine ``caught`` record pre-empts; an *untested* technique is still tried —
    the loop is exactly where that evidence is earned.
    """
    statuses = [resolve(t, result_for(t.key), now=now) for t in for_os(os_name)]
    order = [s.technique.key for s in recommend(statuses)]
    caught = {s.technique.key for s in statuses if s.verdict == CAUGHT}
    return order, caught
