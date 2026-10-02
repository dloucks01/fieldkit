# fieldkit/loaders — reference templates

Each file here is a **reference template** for one entry in the
`fieldkit/weaponization.py` catalog. They are read-only inside fieldkit
— the engine never compiles or executes them. The operator inspects
them to understand the shape, then adapts them for the engagement in
their own arsenal.

## Why templates live here, not in arsenal

The catalog metadata in `fieldkit/weaponization.py` describes WHAT a
technique is. The templates in this directory describe HOW it looks
in code — the actual syscall stub, the AMSI patch bytes, the
beacon's HTTP shape. Together they give the operator enough context to
reach for the right tool from their arsenal without having to re-derive
the technique from a blog post.

File extensions:
- `.c.j2` — C source with Jinja-style placeholders for operator config
- `.cs.j2` — C# source
- `.asm` — raw assembly fragment
- `.py.j2` — Python (for cross-platform beacons / helpers)
- `.ps1.j2` — PowerShell

Templates are documentation, not implementations. fieldkit stays
stdlib-only; placeholder substitution + build + sign + encode happens
in the operator's own toolchain.

## Rendering

```
fieldkit weaponization render <key>
```

Prints the template body + the catalog metadata header. Operators
redirect to disk + hand it to their arsenal.
