# fieldkit TTPs

Techniques as data. Every YAML file in this directory is one MITRE ATT&CK
technique fieldkit can detect + execute + verify + report on. The engine loads
the library at startup (`fieldkit.ttps.load_all()`), merges with any remaining
inlined drivers, and the operator sees ranked opportunities on Analyze /
Dashboard exactly the same way as before.

Adding coverage = a pull request against `fieldkit/ttps/*.yaml` — no Python.

## Schema (version 1)

See `schema.py` for the field-by-field spec. A minimal file:

```yaml
technique: T1548.003
name: Sudo → root via find (GTFOBins)
tactic:  [privilege-escalation]
platform: [linux]
ranking:
  exploitability: high         # high | medium | low
  safety:         config-change # read-only | config-change | crash-risk
  detection:      quiet         # quiet | moderate | loud
detect:
  # exactly ONE of: always, sudo_allows, suid, capability, facts_match
  sudo_allows: find
execute:
  command: "sudo find . -exec id \\; -quit"
verify:
  success: "uid=0"              # substring the output must contain
  proof:   ""                   # optional alternate proof-only command
cleanup:
  command: ""                   # optional reversal
report:
  vector_type: sudo_gtfo_find
  description: "…"
  remediation: "…"
  refs: [T1548.003, GTFOBins/find]
```

## Naming

`Tcode-slug.yaml` — e.g. `T1548.003-sudo-find.yaml`. Sort-friendly and the T-code
prefix makes coverage-per-tactic easy to eyeball.

## Detect predicates

Phase B1 supports:

| Predicate         | Meaning                                                     |
|-------------------|-------------------------------------------------------------|
| `always: true`    | Always applicable (rare — for TTPs the engine tries anyway) |
| `sudo_allows: <b>`| A sudoers entry allows the current user to run `<b>`        |
| `suid: <b>`       | Binary `<b>` is setuid-root                                 |
| `capability: <c>` | Filesystem capability `<c>` is present on a matching binary |
| `facts_match: {}` | Attribute-equality against `HostFacts` (fallback)           |

Richer predicates (version windows, group membership, service state) land in
Phase B2+ as the port work needs them.

## Ranking

Same three-axis rank as `fieldkit.kb.score`. Values are enums, not scores;
`kb.score` computes the sortable integer at analyze time. A quiet, safe,
high-impact, precondition-met TTP floats to the top of Analyze.

## Ports in progress

The strategy plan calls for ~30 initial YAML files by end of Phase B, covering
what `fieldkit.privesc.py`'s inlined tables already do:

  * `privesc.GTFO` (Linux sudo / SUID → root)
  * `privesc.CAPS` (Linux capability abuse)
  * `privesc.WIN_PRIVS` (Windows privileges: SeImpersonate → Potato variants)

Each row of those tables becomes one YAML file; the engine's inlined driver
shrinks as YAMLs cover it. Once ports complete, Phase B5 adds new coverage
(coerce chain, LLMNR, SCCM NAA, container escape, ADCS variants).

## Refreshing the vendored YAML parser

PyYAML ships in `fieldkit/vendor/` alongside Textual. To refresh:

```bash
pip install --target /tmp/yaml-out pyyaml
rsync -a --delete /tmp/yaml-out/yaml/ fieldkit/vendor/yaml/
rsync -a --delete /tmp/yaml-out/_yaml/ fieldkit/vendor/_yaml/
```

Update the version in `fieldkit/vendor/README.md`.
