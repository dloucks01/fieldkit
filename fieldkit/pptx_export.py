"""PPTX executive deck exporter — stdlib-only.

Produces an Open XML .pptx file suitable for a stakeholder read-out
without taking a hard dependency on python-pptx (fieldkit's engine is
stdlib-only).

The .pptx format is a ZIP archive of XML files. This module hand-rolls
the minimal subset the PowerPoint / Keynote / LibreOffice Impress
readers accept: content types manifest + presentation descriptor +
slide master + slide layouts + per-slide XML. We stay in the
"Office Open XML Simple Types" subset so the output opens cleanly
across every modern reader.

Deck shape (5 slides):
  1. Title + scope
  2. Severity breakdown (Critical / High / Medium / Low / Info counts)
  3. Top-5 proven findings
  4. Narrative (prose paragraph from fieldkit.timeline)
  5. Remediation summary

Branding is supplied via a ``BrandConfig`` dict (title color, accent,
footer text, optional logo as PNG bytes). An empty brand config
produces a readable default-styled deck."""
import io
import zipfile
from dataclasses import dataclass
from typing import Optional
from xml.sax.saxutils import escape as _xml_escape


@dataclass(frozen=True)
class BrandConfig:
    """Visual + text branding for the deck.

    ``title_rgb`` / ``accent_rgb`` are six-digit hex colors (no leading #).
    ``footer`` is a short line stamped on every slide (customer name,
    engagement date, "CONFIDENTIAL" marker — operator's call).
    ``logo_png`` is optional PNG bytes to display on the title slide."""
    title_rgb: str = "1a1a1a"
    accent_rgb: str = "0366d6"
    footer: str = ""
    logo_png: Optional[bytes] = None


def _esc(s):
    return _xml_escape(str(s) if s is not None else "")


# --------------------------------------------------------------- xml templates


_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
{slide_overrides}
<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
</Types>
"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>
"""

_PRESENTATION_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldMasterIdLst>
<p:sldMasterId id="2147483648" r:id="rIdMaster"/>
</p:sldMasterIdLst>
<p:sldIdLst>{slide_ids}</p:sldIdLst>
<p:sldSz cx="9144000" cy="6858000"/>
<p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>
"""

_PRESENTATION_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdMaster" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>
<Relationship Id="rIdTheme" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>
{slide_rels}
</Relationships>
"""

_SLIDE_MASTER = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree>
<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
<p:grpSpPr/>
</p:spTree></p:cSld>
<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rIdLayout"/></p:sldLayoutIdLst>
</p:sldMaster>
"""

_SLIDE_MASTER_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdLayout" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
<Relationship Id="rIdTheme" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>
"""

_SLIDE_LAYOUT = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
  type="title" preserve="1">
<p:cSld><p:spTree>
<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
<p:grpSpPr/>
</p:spTree></p:cSld>
</p:sldLayout>
"""

_SLIDE_LAYOUT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdMaster" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>
"""

_THEME = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="fieldkit">
<a:themeElements>
<a:clrScheme name="fieldkit">
<a:dk1><a:srgbClr val="{title_rgb}"/></a:dk1>
<a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>
<a:dk2><a:srgbClr val="333333"/></a:dk2>
<a:lt2><a:srgbClr val="F6F8FA"/></a:lt2>
<a:accent1><a:srgbClr val="{accent_rgb}"/></a:accent1>
<a:accent2><a:srgbClr val="CB2431"/></a:accent2>
<a:accent3><a:srgbClr val="E36209"/></a:accent3>
<a:accent4><a:srgbClr val="DBAB09"/></a:accent4>
<a:accent5><a:srgbClr val="28A745"/></a:accent5>
<a:accent6><a:srgbClr val="6A737D"/></a:accent6>
<a:hlink><a:srgbClr val="{accent_rgb}"/></a:hlink>
<a:folHlink><a:srgbClr val="6A737D"/></a:folHlink>
</a:clrScheme>
<a:fontScheme name="fieldkit">
<a:majorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>
<a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont>
</a:fontScheme>
<a:fmtScheme name="fieldkit">
<a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>
<a:lnStyleLst><a:ln/><a:ln/><a:ln/></a:lnStyleLst>
<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>
<a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>
</a:fmtScheme>
</a:themeElements>
</a:theme>
"""

_SLIDE_SHELL = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree>
<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
<p:grpSpPr/>
{shapes}
</p:spTree></p:cSld>
</p:sld>
"""

_SLIDE_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdLayout" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
</Relationships>
"""


# --------------------------------------------------------------- shape helpers


def _text_shape(sp_id, x_emu, y_emu, w_emu, h_emu, lines, font_size_pt=18,
                 bold=False, color_rgb=None):
    """Return a <p:sp>...</p:sp> element containing a text box.

    EMU = English Metric Units; 914400 EMU = 1 inch; 9144000 x 6858000 =
    standard 10"x7.5" slide. ``lines`` is a list of (text, color_override)
    tuples OR plain strings. ``font_size_pt`` is in half-points (18 →
    "1800" in OOXML)."""
    sz = font_size_pt * 100
    runs = []
    for item in lines:
        if isinstance(item, tuple):
            text, color = item
        else:
            text, color = item, color_rgb
        color_el = f'<a:solidFill><a:srgbClr val="{color}"/></a:solidFill>' if color else ""
        bold_attr = ' b="1"' if bold else ""
        runs.append(
            f'<a:p><a:r><a:rPr lang="en-US" sz="{sz}"{bold_attr}>'
            f'{color_el}</a:rPr><a:t>{_esc(text)}</a:t></a:r></a:p>')
    body = "".join(runs)
    return (
        f'<p:sp><p:nvSpPr><p:cNvPr id="{sp_id}" name="t{sp_id}"/>'
        '<p:cNvSpPr txBox="1"/><p:nvSpPr/><p:nvPr/></p:nvSpPr>'
        f'<p:spPr><a:xfrm><a:off x="{x_emu}" y="{y_emu}"/>'
        f'<a:ext cx="{w_emu}" cy="{h_emu}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
        f'<p:txBody><a:bodyPr wrap="square" rtlCol="0"/><a:lstStyle/>'
        f'{body}</p:txBody></p:sp>')


# --------------------------------------------------------------- slide builders


_SEV_COLOR = {"Critical": "CB2431", "High": "E36209",
              "Medium": "DBAB09", "Low": "28A745", "Info": "6A737D"}


def _footer_shape(brand):
    if not brand.footer:
        return ""
    return _text_shape(99, 457200, 6400800, 8229600, 300000,
                       [(brand.footer, "6A737D")], font_size_pt=10)


def _title_slide(engagement, brand):
    shapes = []
    shapes.append(_text_shape(2, 457200, 2200000, 8229600, 800000,
                              [engagement.get("name") or "engagement"],
                              font_size_pt=44, bold=True,
                              color_rgb=brand.title_rgb))
    shapes.append(_text_shape(3, 457200, 3100000, 8229600, 500000,
                              [f"Scope: {engagement.get('scope') or '(no scope)'}"],
                              font_size_pt=20,
                              color_rgb=brand.accent_rgb))
    shapes.append(_text_shape(4, 457200, 3700000, 8229600, 400000,
                              ["executive readout"], font_size_pt=14,
                              color_rgb="6A737D"))
    shapes.append(_footer_shape(brand))
    return _SLIDE_SHELL.format(shapes="".join(shapes))


def _severity_slide(proven_findings, brand):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in proven_findings:
        sev = f.get("severity") or "Medium"
        counts[sev] = counts.get(sev, 0) + 1
    shapes = [_text_shape(2, 457200, 457200, 8229600, 600000,
                          ["Severity breakdown"], font_size_pt=28, bold=True,
                          color_rgb=brand.title_rgb)]
    y = 1400000
    sp_id = 10
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        if counts[sev] == 0:
            continue
        shapes.append(_text_shape(sp_id, 457200, y, 2500000, 450000,
                                  [sev], font_size_pt=22, bold=True,
                                  color_rgb=_SEV_COLOR[sev]))
        shapes.append(_text_shape(sp_id + 1, 3000000, y, 2500000, 450000,
                                  [str(counts[sev])], font_size_pt=22,
                                  color_rgb=brand.title_rgb))
        y += 550000
        sp_id += 2
    shapes.append(_footer_shape(brand))
    return _SLIDE_SHELL.format(shapes="".join(shapes))


def _top_findings_slide(proven_findings, brand):
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    top = sorted(proven_findings,
                 key=lambda f: (sev_rank.get(f.get("severity", "Info"), 4),
                                 f.get("affected_host", "")))[:5]
    shapes = [_text_shape(2, 457200, 457200, 8229600, 600000,
                          ["Top findings"], font_size_pt=28, bold=True,
                          color_rgb=brand.title_rgb)]
    y = 1400000
    sp_id = 10
    for f in top:
        sev = f.get("severity", "Info")
        shapes.append(_text_shape(sp_id, 457200, y, 1200000, 400000,
                                  [sev], font_size_pt=14, bold=True,
                                  color_rgb=_SEV_COLOR.get(sev, "6A737D")))
        line = (f"{f.get('vector_type','?')} on "
                f"{f.get('affected_host','?')}")
        shapes.append(_text_shape(sp_id + 1, 1800000, y, 6900000, 400000,
                                  [line], font_size_pt=14,
                                  color_rgb=brand.title_rgb))
        y += 480000
        sp_id += 2
    if not top:
        shapes.append(_text_shape(10, 457200, 1400000, 8229600, 400000,
                                  ["(no proven findings)"], font_size_pt=16,
                                  color_rgb="6A737D"))
    shapes.append(_footer_shape(brand))
    return _SLIDE_SHELL.format(shapes="".join(shapes))


def _narrative_slide(narrative, brand):
    shapes = [_text_shape(2, 457200, 457200, 8229600, 600000,
                          ["Engagement narrative"], font_size_pt=28, bold=True,
                          color_rgb=brand.title_rgb),
              _text_shape(3, 457200, 1400000, 8229600, 4200000,
                          [narrative], font_size_pt=14,
                          color_rgb=brand.title_rgb),
              _footer_shape(brand)]
    return _SLIDE_SHELL.format(shapes="".join(shapes))


def _remediation_slide(proven_findings, brand):
    # Count by vector_type — the operator reads "address writable_cron on 4
    # hosts" from this slide
    by_vt = {}
    for f in proven_findings:
        vt = f.get("vector_type", "?")
        by_vt[vt] = by_vt.get(vt, 0) + 1
    top_vts = sorted(by_vt.items(), key=lambda kv: -kv[1])[:6]
    shapes = [_text_shape(2, 457200, 457200, 8229600, 600000,
                          ["Remediation priorities"], font_size_pt=28, bold=True,
                          color_rgb=brand.title_rgb)]
    y = 1400000
    sp_id = 10
    for vt, n in top_vts:
        shapes.append(_text_shape(sp_id, 457200, y, 6400000, 400000,
                                  [vt], font_size_pt=16,
                                  color_rgb=brand.title_rgb))
        shapes.append(_text_shape(sp_id + 1, 7000000, y, 1600000, 400000,
                                  [f"{n} finding(s)"], font_size_pt=14,
                                  color_rgb=brand.accent_rgb))
        y += 480000
        sp_id += 2
    if not top_vts:
        shapes.append(_text_shape(10, 457200, 1400000, 8229600, 400000,
                                  ["(no proven findings to remediate)"],
                                  font_size_pt=16, color_rgb="6A737D"))
    shapes.append(_footer_shape(brand))
    return _SLIDE_SHELL.format(shapes="".join(shapes))


# --------------------------------------------------------------- packager


def render(engagement, findings, narrative="",
            brand=None):
    """Build a 5-slide PPTX deck. Returns the bytes of the .pptx file.

    ``engagement`` + ``findings`` are the shapes report.build() emits.
    ``narrative`` is a short prose summary (from timeline.render_narrative)
    — pass empty string for a blank narrative slide.
    ``brand`` is a BrandConfig (defaults applied if None)."""
    if brand is None:
        brand = BrandConfig()
    proven = [f for f in findings if f.get("proven", True)]

    slides = [
        _title_slide(engagement, brand),
        _severity_slide(proven, brand),
        _top_findings_slide(proven, brand),
        _narrative_slide(narrative or "(no narrative provided)", brand),
        _remediation_slide(proven, brand),
    ]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        overrides = "".join(
            f'<Override PartName="/ppt/slides/slide{i + 1}.xml" '
            f'ContentType="application/vnd.openxmlformats-officedocument.'
            f'presentationml.slide+xml"/>'
            for i in range(len(slides)))
        z.writestr("[Content_Types].xml",
                   _CONTENT_TYPES.format(slide_overrides=overrides))
        z.writestr("_rels/.rels", _ROOT_RELS)

        slide_ids = "".join(
            f'<p:sldId id="{256 + i}" r:id="rIdSlide{i + 1}"/>'
            for i in range(len(slides)))
        slide_rels = "".join(
            f'<Relationship Id="rIdSlide{i + 1}" '
            f'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            f'relationships/slide" Target="slides/slide{i + 1}.xml"/>'
            for i in range(len(slides)))
        z.writestr("ppt/presentation.xml",
                   _PRESENTATION_XML.format(slide_ids=slide_ids))
        z.writestr("ppt/_rels/presentation.xml.rels",
                   _PRESENTATION_RELS.format(slide_rels=slide_rels))

        z.writestr("ppt/slideMasters/slideMaster1.xml", _SLIDE_MASTER)
        z.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels",
                   _SLIDE_MASTER_RELS)
        z.writestr("ppt/slideLayouts/slideLayout1.xml", _SLIDE_LAYOUT)
        z.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels",
                   _SLIDE_LAYOUT_RELS)
        z.writestr("ppt/theme/theme1.xml", _THEME.format(
            title_rgb=brand.title_rgb, accent_rgb=brand.accent_rgb))

        for i, slide_xml in enumerate(slides):
            z.writestr(f"ppt/slides/slide{i + 1}.xml", slide_xml)
            z.writestr(f"ppt/slides/_rels/slide{i + 1}.xml.rels",
                       _SLIDE_RELS)
    return buf.getvalue()


def render_to_file(path, engagement, findings, narrative="",
                    brand=None):
    """Convenience wrapper: render + write to ``path``. Returns the
    byte count of the produced file."""
    data = render(engagement, findings, narrative=narrative, brand=brand)
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)
