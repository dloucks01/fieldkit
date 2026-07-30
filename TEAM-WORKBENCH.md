# TEAM-WORKBENCH.md — design record

**Status:** design complete, not implemented. Set aside pending decision to build.
**Last touched:** 2026-07-30.

This document captures the design decisions from the multi-tester workbench
conversation so the work can be picked up cleanly later. Nothing here is code —
it's the shape of the thing, so if we come back in three months we're not
re-deriving it from scratch.

---

## The problem it solves

The tool is well-shaped for a solo tester. On a multi-tester engagement (2-4
people, same LAN, all trusted), there is currently **no team surface**: no
shared state, no shared visibility, no shared report. The team's current
behavior is that nobody shares findings during an engagement — the leader
consolidates at the end. The workbench is the mechanism that changes that.

The whole design is calibrated against one hard rule: **it must be easier to
share than to stay silent**. If any part of it adds friction to a tester's
existing workflow, they'll bypass it, and once one tester bypasses it, the
group discipline collapses.

## Scope constraints (decided)

- **2-4 testers**, no more. All trusted, all on the same LAN.
- **80% of the team's tool time is outside fieldkit** (nmap, nxc, Burp Pro,
  Metasploit, Ghidra, impacket, etc.). The workbench is primarily a shared
  state hub for arbitrary tools, not a fieldkit-native orchestrator.
- **Same tool versions across the team** — no version negotiation concerns.
- **No shared history yet** — the team currently doesn't share findings during
  an engagement at all. This is a workflow adoption problem as much as a
  technical one.
- **Highly polished, professional look** — non-negotiable. If it looks amateur
  it won't be adopted; half-polished undermines the whole premise.
- **No new pain points** — the workbench can't require attention, memorization,
  configuration, or interruption of the tester's existing flow.

## Architecture (decided)

**Client-executes, server-aggregates.** Each tester's laptop runs their own
tools (nxc, nmap, Burp, etc.) and posts results to a shared server. The server
does not run any of the driven tools — it's a state hub, not an execution
engine.

```
                    ┌─────────────────────────────┐
                    │  LEADER LAPTOP  (state hub) │
                    │                             │
                    │  fieldkit serve             │
                    │    ├─ HTTP+TLS on :8443     │
                    │    ├─ SQLite (single writer)│
                    │    ├─ SSE event stream      │
                    │    └─ Serves the workbench  │
                    │       web app (static)      │
                    └────────────┬────────────────┘
                                 │  HTTPS + shared token
             ┌───────────────────┼───────────────────┐
             │                   │                   │
        ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
        │  Alice  │         │   Bob   │         │ Charlie │
        │         │         │         │         │         │
        │ tools   │         │ tools   │         │ tools   │
        │ locally │         │ locally │         │ locally │
        │         │         │         │         │         │
        │ browser │         │ browser │         │ browser │
        │ tab open│         │ tab open│         │ tab open│
        │ to      │         │ to      │         │ to      │
        │ workbench          │ workbench          │ workbench
        └─────────┘         └─────────┘         └─────────┘
```

Every write to the shared state records:
- **Who** did it (`tester`, from `FIELDKIT_TESTER` env)
- **What tool** produced it (`source`: `nxc`, `nmap`, `burp`, `manual`, `custom:<script>`)
- **When** (already in schema)

Attribution is for the report and audit trail, not for authorization — trust
is assumed among team members.

## The workbench itself (decided shape)

**A polished web app served by the fieldkit server.** Not a TUI, not a
background daemon, not a shell integration. Web because:

1. Zero-install per tester — click a URL, browser tab, done.
2. Professional look ceiling — TUIs can look sharp but can't do rich
   typography, images, animations.
3. Cross-platform without effort.
4. Fits the pentesting audience's mental model — Burp Pro, Nessus, Metasploit
   Pro, Sliver dashboards are all web.

The workbench is **always-open, glance-optional**. Testers keep it in a tab
next to their terminal. They look at it when curious about team state.
Nothing punishes not looking.

### The 4 primary views

Not 6. Consolidated for cognitive load:

1. **Board** — the landing view. Phase, top 3 next moves, hot hosts (pwned),
   recent activity feed, key stats. Everything a tester needs to answer
   "where are we?" without clicking.
2. **Hosts** — table view. IP, hostname, OS, status pills, owner, findings
   count. Click a row → detail pane with tabs for steps / findings / creds /
   notes for that host. Credentials fold in here; no separate creds screen.
3. **Findings** — the deliverable-in-progress. Severity chips, host,
   discoverer, tool source, evidence preview. Filter by severity, tester,
   tool, host. Click → full detail with evidence + screenshots + steps.
4. **Reports** — generate + preview. The end-of-engagement payoff view.

Notes and creds are **NOT their own screens** — they live inside host detail
so testers don't have to context-switch.

### The one keyboard shortcut

**⌘K opens command palette.** That's the only shortcut testers need to
memorize. Everything else is fuzzy-searchable:

- "new finding"
- "add note"
- "paste output" (auto-detects: nmap XML, nxc log, hashcat pot, etc.)
- "new credential"
- "go to host 10.0.0.7"
- "search Jenkins"

No single-letter shortcuts per screen. No modes. No cheat sheet to memorize.
Discoverable through the palette; muscle memory develops naturally through use.

### The zero-pain design rules

Every screen, every interaction has to pass this test:

1. **Ignoring costs nothing** — no badges, no dots, no red counters, no
   notifications, no "you haven't checked in for X hours" nags. Complete
   indifference to whether the tester is looking.
2. **Contributing takes < 10 seconds** — cmd+K → search action → do it → done.
   Every capture flow measured against this bar. Forms have 2-3 fields max
   defaulted to sensible values.
3. **Nothing interrupts** — no modals, no toasts, no focus theft. Server
   hiccups show a small "Reconnecting..." chip in the corner, never a modal.

### What the workbench specifically DOES NOT DO

- No notifications (ever)
- No login flow — leader shares a URL like `https://leader:8443/w/<token>`,
  first click stores the token, forever
- No settings menu — one theme, one layout, one aesthetic
- No preferences to configure
- No onboarding tour or "get started" nudges
- No @mentions, chat, threads, comments (Slack does that)
- No task assignment, time tracking, KPIs
- No attack graph visualization (looked at, ruled out — graph viz always
  underdelivers vs a ranked list of the same information)
- No modals with confirmation dialogs — undo instead of confirm
- No presence pings ("Alice just came online") — a subtle static
  "online: alice, bob" chip is fine, motion/toast is not

## External tool integration (decided model)

The workbench is not a wrapper around tools. Testers run their tools exactly
as they always have — no prefix, no shell integration, no behavior change.
Findings come into the shared engagement via three paths:

**1. Paste-and-auto-detect.**
The primary flow. Tester runs a tool, copies its output, hits ⌘K → "paste
output" → paste. Workbench detects the format (nmap XML, nxc log, hashcat pot,
etc.) and ingests it. Also works as `fieldkit ingest paste <file>` in the CLI.

**2. Quick note.**
For the "I just found this thing, worth knowing" case. ⌘K → "note" → type →
enter. Attached to a host if specified, floating otherwise. Takes 3-5 seconds.
Also available as `fieldkit ingest note "..."` from the CLI.

**3. Structured finding.**
For real findings from external tools. Small form: type, host, title,
evidence file/paste, severity. Submits to shared engagement. Also available
as `fieldkit ingest finding --type X --host Y --title Z --evidence @file`.

Format-specific parsers to build for the team's declared tool set: **nmap XML**,
**nxc log** (already exists via `ingest nxc`), **hashcat pot**, **impacket
secretsdump output**, **Burp Pro report export** (JSON/XML), **BloodHound zip**
(partial coverage today via `bloodhound import`).

Metasploit and Ghidra can't be wrapped (interactive/GUI); those get manual
`note` and `finding` capture.

**Optional wrappers** (nice-to-have, not required for adoption): thin shell
scripts `fk-nmap`, `fk-nxc`, `fk-hashcat` that auto-ingest without a
manual paste step. Ship as a separate download; testers who want zero-effort
capture install them, testers who don't just paste manually. Neither path is
"the right way"; both feed the same store.

## Aesthetic direction (undecided — needs the leader's calls)

The leader is the single design decision-maker. Not committee, not consensus,
one person. When resuming this work, need decisions on:

1. **Aesthetic references** — 3-4 apps whose look/feel is the target. Only
   partial: pentesters usually reach for Linear, Raycast, Sliver dashboard,
   or Metasploit Pro as reference points. Undecided.
2. **Density** — spacious (Linear/Notion) vs dense (k9s/Bloomberg). Pentesters
   usually lean dense, but that's a taste call. Undecided.
3. **Palette** — dark-first (probably). Pure black vs soft dark (#0F0F10). Undecided.
4. **Type family** — Inter, IBM Plex Sans, JetBrains Mono for code, or other. Undecided.
5. **Accent color** — the biggest single tone-setter. Undecided.
6. **Icon set** — Lucide, Phosphor, Heroicons, Radix. Undecided.
7. **Sidebar vs top-nav** — for the 4 primary views. Undecided.
8. **Card vs table** — for Hosts and Findings. Undecided.
9. **Motion tone** — Framer-Motion-expressive vs minimal fades. Undecided.

Consistency across all 9 is what makes it look bought instead of built.

## Tech stack (decided direction, pending confirmation)

- **Backend:** Python (existing fieldkit) + FastAPI on top of Store methods.
  Serves the static workbench build from the same port.
- **Frontend:** React + TypeScript + Vite + Tailwind + shadcn/ui.
  This gets 80% of "professional look" for free without a designer full-time.
- **Realtime:** SSE (Server-Sent Events). Simpler than WebSocket, fits the
  append-mostly nature of the shared state.
- **State:** TanStack Query for server state; minimal client state.
- **Charts:** Tremor or Recharts (small use).
- **Motion:** Framer Motion (used sparingly).

The Python fieldkit codebase stays stdlib-only. The workbench is a separate
subtree with its own build. `fieldkit serve --workbench` starts both.

## Phased build plan (undecided — not committing yet)

Rough scope for the "no new pain, highly polished" version:

| Phase | Content | Rough scope |
|---|---|---|
| **1** | Store abstraction — extract `Store` as a formal interface, `LocalStore` = current SQLite, prove tests still pass with no behavior change. Load-bearing refactor. | ~1 week |
| **2** | Server: `fieldkit serve` with FastAPI over Store methods. Shared token auth. Self-signed TLS. Read + write endpoints. `RemoteStore` client for native fieldkit commands over HTTP. Attribution column (`tester`). | ~1.5 weeks |
| **3** | Frontend foundation: Vite + React + TS + Tailwind + shadcn/ui scaffold. Auth flow (paste URL + token OR tokenized URL). Layout shell. Design tokens (color palette, type scale, spacing). Basic components (button, table, badge, dialog, command palette skeleton). | ~1 week |
| **4** | Core screens: Board + Hosts + Findings + Reports. Each is a real page with filters, detail panes, actions. | ~3 weeks |
| **5** | Command palette + live sync: ⌘K palette with fuzzy search and quick-capture actions. SSE integration so everything updates real-time without refresh. | ~1 week |
| **6** | Polish: animations, empty states designed for day-1, loading skeletons, error states, keyboard shortcuts overlay (`?`), small-screen testing (13" MacBook is the constraint). | ~1-1.5 weeks |
| **6b** (parallel) | Ingest CLI + format parsers: `fieldkit ingest paste`, `ingest nmap`, `ingest burp`, `ingest hashcat`, `ingest note`, `ingest finding`. | ~1 week |

**Total: 6-8 weeks focused work for a truly polished MVP.**

Explicitly NOT in MVP: attack graph, screenshot inline in report, Burp
extension, browser-based bulk operations, mobile-responsive views, third-party
tool marketplace, advanced report editor.

**Recommended de-risking:** before committing 6-8 weeks, do a **1-week
mockup**. Static React app, mocked data, just the Board screen styled exactly
as the finished product would look. Show the team; specifically ask "would you
close this tab or leave it open?" If they'd leave it, commit. If not, course-
correct without sinking the full build.

## Risks I want documented

1. **"Professional" is subjective and moving.** What looks professional in
   2026 doesn't in 2028. If we commit to premium, we're committing to periodic
   design refreshes — realistic maintenance is 2-4 weeks/year.
2. **Scope creep is nearly inevitable.** Every screen invites "wouldn't it be
   cool if..." The discipline is: MVP is done when the 4 screens work well,
   and nothing else ships until then.
3. **Adoption failure is the whole downside.** A CLI that isn't adopted is
   still useful to the leader who built it. A workbench that isn't adopted is
   6-8 weeks of code sitting idle. Higher stakes.
4. **Cross-browser edge cases.** Web apps mostly work but there's always some
   pain in Safari, Firefox, mobile browsers. Plan a week for it.
5. **Version drift.** If we let the workbench build target a different fieldkit
   API version than the leader's server, testers will see stale data or errors.
   Need to version-lock or version-negotiate. Not decided.

## Open questions to answer before starting

Documented here so we don't forget when we come back:

1. **Aesthetic direction** — see the 9 undecided decisions above. Nothing
   should start until at least decisions 1-5 are made.
2. **Prototype-first or spec-first workflow?** — will the leader spec each
   screen, or does the leader build mockups in Figma/etc. and hand them off?
3. **What does the team use besides the declared tools?** — nmap, nxc, Burp,
   Metasploit, Ghidra, impacket are named. "Among others" needs specifics
   so we know which parsers to build in phase 6b.
4. **When would the first real test be?** — building the workbench without
   a target engagement to test it against means we're guessing at usability.
   Ideal: sync the build to line up with a real engagement 6-8 weeks out.

## Where the design conversation left off

We ended agreed on:
- Web app, not TUI, not wrapper strategy alone
- 4 primary views, not 6
- Zero-pain principles are the design system
- Leader is sole design decision-maker
- Ingest via paste-and-auto-detect + quick note + structured finding
- Wrappers are optional add-ons, not the adoption mechanism
- Recommend 1-week static mockup before committing to full build

We deferred:
- The 9 aesthetic decisions
- Committing to the 6-8 week build
- Which external tools get format-specific parsers beyond the named set
