# fieldkit/vendor

Third-party Python packages vendored so `bin/fieldkit tui` runs on a fresh clone
with no `pip install`. All pure-Python, MIT-licensed. See `LICENSES/` for the
upstream license text of each package.

## Contents

| Package             | Version  | Purpose                                      |
|---------------------|----------|----------------------------------------------|
| `textual`           | 1.0.0    | TUI framework — the app skeleton, widgets    |
| `rich`              | 15.0.0   | terminal rendering (used by textual + us)    |
| `pygments`          | 2.21.0   | syntax highlighting (rich transitive dep)    |
| `markdown_it`       | 4.2.0    | markdown parsing (rich transitive dep)       |
| `mdit_py_plugins`   | 0.6.1    | markdown-it plugins (rich transitive dep)    |
| `mdurl`             | 0.1.2    | markdown-it URL helper (rich transitive dep) |
| `uc_micro`          | 2.0.0    | unicode helper (markdown-it transitive dep)  |
| `linkify_it`        | 2.1.1    | link detection (markdown-it transitive dep)  |
| `platformdirs`      | 4.11.5   | user-dirs helper (textual transitive dep)    |
| `typing_extensions` | 4.16.0   | typing back-compat (single .py file)         |

## How the path shim works

`fieldkit/tui/__init__.py` prepends this directory to `sys.path` at import
time, so `import textual` inside `fieldkit.tui.*` picks up the vendored copy.
Non-TUI code never triggers the shim, so a system install of a different
`textual` version (if the operator has one) does not conflict elsewhere.

## Refreshing the vendored copies

```bash
# from repo root
python3 -m venv /tmp/vendor-refresh && \
  /tmp/vendor-refresh/bin/pip install --target /tmp/vendor-out 'textual>=1,<2'
# review the diff, then:
rsync -a --delete /tmp/vendor-out/ fieldkit/vendor/
find fieldkit/vendor -name __pycache__ -type d -exec rm -rf {} +
```

Bump the version numbers in this file when refreshing so a future you can tell
what's here without inspecting every dist-info.
