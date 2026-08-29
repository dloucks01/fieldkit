"""The TUI's visual language, as one source of truth.

Every widget in :mod:`fieldkit.tui` reads palette, glyphs, and text-styles from
here — never from a color literal, never from a magic string, so a palette
adjustment is a single-file change. The rules live in the ``The Operator View``
design brief; this module is their code manifestation.

Two hard rules on how colors are used (from §2 of the brief):

  1. **The accent is one color.** Burnt orange marks the next move (section
     header, primary-action arrow, focus). Semantic status colors — critical
     rust, moss good, indigo info — carry *state*. They never impersonate the
     accent, and the accent never impersonates state.

  2. **Never color-only for meaning.** Every semantic state also carries a
     glyph, so deuteranopia and low-contrast terminals stay legible.
"""


class C:
    """Palette. Named colors — always via constants, never as literals in widgets."""

    #: Ground — deep warm charcoal (not pure black). Page background, panel bg.
    BG = "#17140F"
    #: Elevated surface (selected row, active pane header background).
    SURFACE = "#1F1C15"
    #: Primary text — warm off-white.
    INK = "#ECE4D0"
    #: Secondary text (labels, section-header meta).
    INK_DIM = "#A8A090"
    #: Tertiary text (timestamps, ids, whitespace fillers).
    INK_DIM2 = "#6B6255"
    #: Frames, rules, dividers.
    RULE = "#38322A"
    #: THE accent — the one focus color. Next move, ▸, keyboard shortcuts,
    #: focused input caret. Nothing else uses it.
    ACCENT = "#E38B4A"
    #: Critical / caught / error.
    CRIT = "#D4635A"
    #: Good / proven / lab-green / success.
    GOOD = "#7CAC66"
    #: Info / observation / notice.
    INFO = "#7A90B3"
    #: Warning — deliberately the same value as ACCENT because attention IS
    #: the accent. Present as its own name so a widget's intent reads clearly.
    WARN = "#E38B4A"


class G:
    """Glyph inventory. Unicode-only (no Nerd Font requirement).

    Every glyph carries a specific meaning — the list is closed, and the TUI
    does not add icons for decoration. See §4 of the design brief.
    """

    #: Action step / subsection header prefix.
    ACTION = "▸"
    #: Severity dot — filled (present).
    SEV_ON = "●"
    #: Severity dot — empty (absent).
    SEV_OFF = "○"
    #: Proven finding (captured evidence exists).
    PROVEN = "★"
    #: Observation (identified, not proven).
    OBSERVATION = "◇"
    #: Caught by evasion (EDR triggered) / error.
    CAUGHT = "⚠"
    #: Escalation (privilege gained).
    ESCALATION = "↑"
    #: Route / lateral movement / pivot.
    ROUTE = "→"
    #: Running / action in-flight.
    RUNNING = "⏵"
    #: Paused (watch stopped).
    PAUSED = "⏸"


def severity_dots(severity):
    """Render a severity as its three-dot cluster: `●●●`, `●●○`, `●○○`, `○○○`.

    Consumers use ``severity_dots(finding_severity)`` to encode severity
    redundantly with color, so a scan reads density before it reads text.
    """
    filled = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}.get(
        (severity or "").lower(), 0)
    return G.SEV_ON * filled + G.SEV_OFF * (3 - filled)


def severity_color(severity):
    """The palette color for a severity tier, matching the design's rules."""
    sev = (severity or "").lower()
    if sev == "critical":
        return C.CRIT
    if sev == "high":
        return C.WARN     # accent — attention IS the color
    if sev == "medium":
        return C.INFO
    return C.INK_DIM


# ---------------------------------------------------------------------------
# Textual CSS — the master style block. Every screen `.tcss` file (once we add
# per-screen ones) can override, but the App-level styles set the frame and
# palette defaults, so a widget without explicit style still reads on-palette.
# ---------------------------------------------------------------------------
APP_TCSS = f"""
Screen {{
    background: {C.BG};
    color: {C.INK};
}}

/* One-color-per-role: every named class here maps to a role, not a widget kind. */
.dim         {{ color: {C.INK_DIM}; }}
.dim2        {{ color: {C.INK_DIM2}; }}
.accent      {{ color: {C.ACCENT}; }}
.crit        {{ color: {C.CRIT}; }}
.good        {{ color: {C.GOOD}; }}
.info        {{ color: {C.INFO}; }}
.warn        {{ color: {C.WARN}; }}
.rule        {{ color: {C.RULE}; }}
.section     {{ color: {C.ACCENT}; text-style: bold; }}

/* Frame + footer — every screen gets these */
#frame {{
    border: round {C.RULE};
    padding: 1 2;
    background: {C.BG};
}}
#title-bar {{
    color: {C.INK};
    text-style: bold;
    height: 1;
    padding: 0 1;
}}
#title-bar .time {{
    color: {C.INK_DIM};
    text-style: none;
}}
Footer {{
    background: {C.BG};
    color: {C.INK_DIM};
}}
Footer > .footer--key {{
    color: {C.ACCENT};
    background: {C.BG};
    text-style: bold;
}}
Footer > .footer--description {{
    color: {C.INK_DIM};
    background: {C.BG};
}}

/* Stub placeholder for screens still under construction (Ships 2–5). */
.stub {{
    color: {C.INK_DIM};
    padding: 2 4;
    text-align: center;
}}
.stub-glyph {{
    color: {C.ACCENT};
    text-style: bold;
}}
"""
