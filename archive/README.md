# archive/ — the v1 print-only tree

Everything here is the original fieldkit: ~5,600 lines of `gen_*.py` generators that
**print** commands for you to paste. They still run exactly as they did (each script
puts its own directory on `sys.path`, so `python3 archive/linpriv/gtfo.py …` works),
and nothing has been deleted — the move was a `git mv`, so history is intact and
reversible.

They were moved out of the main path because v1 failed on a real >400-host internal
AD engagement for three reasons it could not fix in place: it held **no state**,
parsed **no tool output**, and was **not importable**. v2 supplies those three on top
of the same domain knowledge. See [`../README.md`](../README.md).

| Path | v1 kit | Lifted into v2 by |
|---|---|---|
| `access/network/` | recon, spray, cred→shell, service CVEs, coercion/relay/ADCS, cloud | `nxc.py`, `transport.py`, `ingest/` (Phase 1–2), ADCS/relay (Phase 4) |
| `access/web/`, `access/services/` | initial access — web app and open-service exploitation | `kb/services.py` foothold sources (Phase 1); web stays archived |
| `winpriv/`, `linpriv/` | Windows/Linux privesc tables, `enum.bat`/`enum.sh` | `kb/windows.py`, `kb/linux.py`, `collectors/`, `privesc/` (Phase 1–2) |
| `novelre/` | novel binary vuln research | not part of the v2 engine |
| `configure.sh` | `sed`-edited LHOST/LPORT into tracked source | replaced by `fieldkit config set` (config lives in the engagement DB) |

**Do not use `configure.sh`.** It rewrites tracked source files, which is how a
payload ends up pointing at the previous client's redirector. If you run a v1
generator, edit its `_*_common.py` directly, or read the value from
`fieldkit config get lhost`.
