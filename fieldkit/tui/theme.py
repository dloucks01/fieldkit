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

The palette below flows two places:

  * :class:`C` — Python constants for code that computes colors directly
    (severity_color, per-widget style overrides that can't sit in CSS).
  * :data:`FIELDKIT_DARK` — a Textual :class:`~textual.theme.Theme` registered
    at app startup. Every CSS rule in :data:`APP_TCSS` references its
    variables (``$primary``, ``$fk-ink-dim``, …) so Textual's theme switcher
    can flip fieldkit → gruvbox → dracula → back to fieldkit and everything
    recolors live. The two sources agree by construction — one place changes
    color, both channels update.
"""
from textual.theme import Theme


class C:
    """Palette. Named colors — always via constants, never as literals in widgets."""

    #: Ground — deep warm charcoal (not pure black). Page background, panel bg.
    BG = "#17140F"
    #: Elevated surface (selected row, active pane header background).
    SURFACE = "#1F1C15"
    #: Panel (slightly lighter than surface for nested elevation).
    PANEL = "#26221B"
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


#: Fieldkit's Textual theme. Registered in :class:`~fieldkit.tui.app.FieldkitTUI`
#: at mount and set as the default; Textual's built-in themes stay registered so
#: the Ctrl-P → "Change theme" command still works — gruvbox, dracula, etc. are
#: one keystroke away, and switching back to ``fieldkit-dark`` restores brand.
FIELDKIT_DARK = Theme(
    name="fieldkit-dark",
    # Textual's semantic slots map to our palette by role, so every widget
    # that reads $primary / $accent / $error / $success / $warning /
    # $foreground / $background / $surface / $panel gets on-palette colors
    # automatically — the DataTable, Footer, TextArea, Button, etc.
    primary=C.ACCENT,        # brand — the thing the eye tracks
    secondary=C.INFO,        # supporting — informational
    accent=C.ACCENT,          # same as primary — accent IS the brand
    warning=C.WARN,           # same value as accent (brief §2)
    error=C.CRIT,             # rust
    success=C.GOOD,           # moss
    foreground=C.INK,
    background=C.BG,
    surface=C.SURFACE,
    panel=C.PANEL,
    dark=True,
    # Override the built-in Textual variables that matter to our brand.
    # We deliberately do NOT introduce custom `$fk-*` vars: they would break
    # theme switching (a user swapping to gruvbox would hit an unresolved-var
    # error, since gruvbox has no fk-* keys). Every CSS rule below references
    # canonical Textual variables that exist under every theme; when the
    # operator switches to gruvbox, gruvbox's version of those vars applies —
    # which is what a theme switch should do.
    variables={
        # Border/rule color used across all framed widgets — the subtle warm
        # dark that distinguishes a fieldkit frame from every generic terminal
        # panel. Under gruvbox/dracula/etc. this reverts to that theme's own
        # border color (Textual's default).
        "border": C.RULE,
        "border-blurred": C.RULE,
        # Footer shortcut labels — the accent lives here so the keymap always
        # reads as the brand tracker on fieldkit-dark; on other themes it
        # picks up their accent instead.
        "footer-key-foreground": C.ACCENT,
        "footer-key-background": C.BG,
        # Cursor blocks (input, block-cursor) pick up the accent so focus
        # feels on-brand.
        "block-cursor-foreground": C.BG,
        "block-cursor-background": C.ACCENT,
    },
)


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
# Textual CSS — the master style block. Every color reference is a Textual
# theme variable (``$primary``, ``$fk-ink-dim``) rather than a hex literal, so
# swapping themes recolors the entire TUI live.
# ---------------------------------------------------------------------------
APP_TCSS = """
Screen {
    background: $background;
    color: $foreground;
}

/* One-color-per-role — every named class here maps to a role, not a widget kind.
   Widgets pick a class; the class picks a canonical Textual theme variable so
   the switcher (Ctrl-P → Change theme) recolors everything live. */
.dim         { color: $foreground-muted; }
.dim2        { color: $foreground-disabled; }
.accent      { color: $accent; }
.crit        { color: $error; }
.good        { color: $success; }
.info        { color: $secondary; }
.warn        { color: $warning; }
.rule        { color: $border; }
.section     { color: $accent; text-style: bold; }

/* Frame + title bar — every screen wears these. */
#frame {
    border: round $border;
    padding: 1 2;
    background: $background;
}
#title-bar {
    color: $foreground;
    text-style: bold;
    height: 1;
    padding: 0 1;
}

/* Footer — the persistent keymap strip. Textual 1.0's Footer renders each
   shortcut as a FooterKey child; the theme's `footer-key-foreground` variable
   colors the key labels, so we don't need per-class overrides here. */
Footer {
    background: $background;
    color: $foreground-muted;
}

/* Stub placeholder for screens still under construction (Ships 2–5). */
.stub {
    color: $foreground-muted;
    padding: 2 4;
}
.stub-glyph {
    color: $accent;
    text-style: bold;
}
"""
