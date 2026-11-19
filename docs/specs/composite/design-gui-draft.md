# design-gui — composite native GUI, r2 FINAL (owner approval recorded 2026-11-11: the owner replied "اكمل" to the DEC-11 approval request following the goldfish-integrated presentation — recorded per the standing delegation pattern; implementation may proceed per the sequence below)

> Status: DRAFT per the EGM cycle. Owner raised the requirement 2026-11-10:
> the composite must stop shipping upstream's simplewall GUI; it needs its
> own user-facing UI, friendly, covering the composite feature set. This
> draft proposes the architecture for owner approval BEFORE any
> implementation (hard rule: no implementation before owner approval).

## DEC-11 (proposed): the composite ships its own native Win32 UI, redesigned from scratch

### Problem

The current UI is upstream's simplewall layout (toolbar + tabs + list
views) with composite states bolted onto the status bar/tooltip. It does
not surface the composite value: smart prompting tiers, publisher rules,
lockdown seal, signed packs, (future) ledger + domain layer. Upstream UI
also inherits upstream's layout assumptions that conflict with per-connection
review UX.

### Hard constraints inherited (unchanged unless the owner amends them)

- NFR-02: system libraries only, dynamic-resolve pattern, no new package
  dependencies.
- NFR-03: installed size ≤ 8 MB, single portable binary, no service, no
  driver.
- DEC-01: fork C chassis, no rewrite of the engine.
- Memory footprint stays the marketed differentiator (measured ~48 MB
  session; PROPOSED budget, owner-ratified in this round: idle
  hidden-to-tray stays ~20 MB, pages release bitmaps on hide — asserted
  by the NFR-03 footprint job).

### Options evaluated

| Option | Fits NFR-02/03 | Footprint | Dev cost | Verdict |
|---|---|---|---|---|
| A. Native Win32 redesign (custom-drawn, dark theme, virtualized lists) | YES (100% system libs) | best (~+0-2 MB) | medium | **RECOMMENDED** |
| B. Sciter embedded engine (HTML/CSS UI) | NO — third-party UI engine; design.md permanently rules out alternative UI toolkits | +3-5 MB | low-medium | **REJECTED** (would need an umbrella amendment even to consider) |
| C. WebView2/Tauri-style | NO — webview runtime + extra process | 100 MB+ runtime | medium | REJECTED outright |

### Option A — the composite UI (recommended)

1. **Shell**: same single exe (DEC-01), new main window identity:
   - left navigation rail (Apps / Rules / Packs / Lockdown / Log / Settings)
     replacing upstream's tab bar;
   - dark/light theme drawn by the app (owner-selectable), per-monitor DPI;
   - one global search box filtering the active page (upstream's regex
     search request #2140 superseded).
2. **Apps page**: card-per-app rows (icon, name, publisher badge from
   T004, connection state, tri-state rule) with bulk actions — replaces
   the raw ListView.
3. **Rules page**: composite rule model surfaced: session decisions with
   remaining duration, publisher anchors with materialized-path counts,
   permanent rules; import wizard entry point.
4. **Packs page (new, T008/T009 surface)**: pack list with version,
   signature epoch, enable/disable, anti-rollback state, import button.
5. **Lockdown page (new, T007 surface)**: engage/release with the
   keep-or-release semantics visible BEFORE the action; seal state +
   survival-rule explanation panel; audit pre-flight outcome.
6. **Log page**: per-connection review view (foundation for Phase 2
   ledger): app, remote endpoint, verdict, prompting tier that decided it;
   filter chips (blocked/permitted/held). Held rows carry ACTIONS (r2,
   per goldfish finding 5): allow/block once / until-restart via
   `_app_state_decide` — the FR-05 batch-review loop closes in the UI,
   not view-only.
7. **Prompting**: the existing prompt window is redesigned to carry its
   new data: tier that resolved (auto-tier / publisher / none), duration
   choices with the T005 semantics inline, "held: N connections" line.
8. **Tray**: existing surface (T011) kept: degradation states, held
   counter, [LOCKDOWN] suffix; tray menu gains Packs/Lockdown shortcuts.
9. **i18n**: every string through the localization pipeline from day one
   (NFR-05) — fixes the M4 manual-procedure gap permanently. Settings
   page hosts the composite config gates (r2, per goldfish finding 7):
   `IsCompositeTiersEnabled`, `IsCompositeSingleFlightEnabled`, audit
   subcategory state + revert — named homes, no hidden toggles.
10. **Engine contract (r2, per goldfish finding 1)**: NO WFP/engine-
    behavior changes in the GUI round; the UI consumes the existing
    module APIs PLUS new read-only query APIs added inside the composite
    modules (in scope, enumerated here):
    - packs: enumerate enabled packs (id, version, epoch, watermark
      state), `_app_packs_enable` for the import wizard flow;
    - publisher: enumerate anchors + materialized-path counts;
    - state: session decisions with remaining duration (extends
      `_app_state_getdecision` beyond is_block/is_once);
    - lockdown: pre-flight outcome + snapshot summary for the page.
    The S4 lock discipline (no SendMessages under module locks) is
    restated as a UI-round invariant. These query APIs are additive,
    namespaced, and rebase-cheap (DEC-09).

### Sizing

- New/rewritten UI code ≈ 4-6 kLOC C (owner-drawn controls, no framework).
- Binary delta: ≤ 1 MB (NFR-03 stays trivially met).
- Milestones: M1 shell+theme+Apps (usable replacement) → M2
  Rules/Packs/Lockdown pages → M3 prompting redesign + Log page → M4 i18n
  sweep + phase-out of upstream dialog code.

### Verification

- All Phase 1 bench probes + verification-checklist must stay green with
  the new shell (engine untouched).
- New UI-specific manual procedures: theme switching under DPI change,
  navigation-rail keyboard traversal, screen-reader labels for the rail
  and cards (basic accessibility), pack/lockdown flows end-to-end.
- Footprint job asserts the ≤ 8 MB and idle-RAM budget with the new shell.

### Risks

- Owner-drawn Win32 controls are the cost center (mitigated: no framework
  chase, two-window discipline precedent from the round-2 arena plan).
- Upstream rebase cost: GUI round touches upstream UI files heavily —
  rebase window (2026-12-01) should land BEFORE the GUI rewrite starts to
  minimize conflicts.
- Accessibility is a real scope (basic screen-reader labels in M1, full
  audit later).
- (r2, per goldfish finding 6) ONGOING rebase cost: after M4 deletes
  upstream dialog code, every monthly rebase touches UI by hand — the
  rebase-first window only helps once; keep composite UI in
  fork-namespaced files to contain it (DEC-09 discipline).
- (r2) Rendering budget: owner-drawn cards at 5k apps need a stated
  perf budget (frame < 16 ms on scroll, GDI handles < 10k, per-monitor
  DPI verified) — added to verification procedures.
- (r2) RTL/Arabic layout in owner-drawn controls under NFR-05: mirror
  layout support must be designed in M1, not retrofitted.

## Open questions — resolved by the goldfish round (r2)

1. Rail coverage: no hidden gap EXCEPT the upstream editor (fixed: card
   expansion) and batch-decide (fixed: held-row actions).
2. Tray-only mode: first-class; tray surface is self-contained; pages
   release bitmaps on hide (verification item added).
3. Prompt window: same-process (a separate process violates SEC-05);
   S4 hazard already fixed by the detach-outside-lock pattern.
4. Ledger UI: fix the LOG ROW SCHEMA now (app, endpoint, verdict, tier,
   timestamp — stable columns); do NOT lock FR-10 quarantine UX — ledger
   gets its own page in Phase 2 (rail slot reserved only).

## Sequence proposal (owner decides)

1. Land the 2026-12-01 upstream rebase first.
2. This design → goldfish review → owner approval → spec/plan/tasks
   (T025+) chain.
3. Phase 2 ENGINE work (FR-07/FR-10/FR-11/FR-12, GUI-independent)
   proceeds in parallel on the existing shell; the GUI round consumes it
   when the ledger lands.

---

## r3 amendment (2026-11-19): G-1 implementation mechanics — external-research grounded

> Owner directive for this round: ground the GUI fixes in how OTHER
> mature open-source projects solved the same problems ("بناء على حلول
> وتجارب آخرين وبحثهم") with subagent research. An independent research
> pass verified 11 primary repositories in-clone plus Microsoft docs
> (simplewall/routine upstream, ysc3839/win32-darkmode, Notepad++,
> MPC-HC, TinyWall, WFN, priv10, System Informer, Portmaster, GlassWire,
> NetLimiter; MS list-view overview, LVM_SETITEMCOUNT, Window Layout
> and Mirroring, DWMWINDOWATTRIBUTE, UX-Guide dialogs). Every delta
> below ELABORATES an already-approved key (DEC-11 / NFR-05 / NFR-07 /
> DEC-09) — no architecture change, no new owner-facing decision, so
> this amendment proceeds through goldfish review + gate without a new
> owner approval round. G-1 scope stays rail + theme + Apps page.

### G1-M1: theme engine mechanics (elaborates DEC-11 §2 "dark/light owner-selectable")

- REUSE the vendored routine primitives, no new theming code:
  `_r_theme_setwindowframe` (dark titlebar = DWMWA_USE_IMMERSIVE_DARK_MODE
  attr 20 with the attr-19 pre-20H1 fallback inside routine — matches
  ysc3839/win32-darkmode findings), `_r_wnd_isdarkmodeenabled` (registry
  read; the ShouldAppsUseDarkMode uxtheme ordinal is unreliable ≥1903 —
  the same conclusion routine's own source comments cite,
  win32-darkmode#3).
- The shell carries TWO palettes: dark = mockup-r1.html values (already
  in the scaffold), light = derived counterpart. Owner toggle
  `IsShellLightTheme` (config gate on the Settings page). Auto-detect
  via `_r_wnd_isdarkmodeenabled` when no explicit choice is set;
  WM_SETTINGCHANGE/WM_THEMECHANGED re-evaluate.
- Flicker elimination: BeginBufferedPaint (documented uxtheme API,
  NFR-02 system-lib compliant) — the Notepad++/routine double-buffer
  pattern. WM_ERASEBKGND stays suppressed.
- REJECTED on evidence: IAT-hooking uxtheme (ysc3839's OpenNcThemeData
  ordinal-49 hook) — self-hooking system libraries is unacceptable in a
  hardened security tool. Consequence (documented, accepted): the
  MessageBoxW body stays light in dark mode on <Win11; dark confirm
  surfaces arrive with the M3 owner-drawn prompt redesign. Win11-only
  DWMWA_BORDER_COLOR/CAPTION_COLOR/CORNER_PREFERENCE are documented
  attributes and safe to set opportunistically.
- WM_DPICHANGED: recreate the four fonts + invalidate (per-monitor DPI,
  DEC-11 §2) — the r1 scaffold fixed fonts once at WM_CREATE.
- (r3 integration, goldfish finding 2) DPI-AWARENESS PREREQUISITE: the
  process currently declares NO DPI awareness repo-wide — WM_DPICHANGED
  is never delivered to a DPI-unaware process, so the fix above is a
  dead letter without it. FIX: a fork-owned additional manifest
  (src/gui/composite_dpi.manifest, merged via vcxproj
  AdditionalManifestFiles) declaring PerMonitorV2 — manifest applies
  before any window exists and needs no per-OS code gating. Verified
  repro: 150% display — before: DWM bitmap-stretched text; after:
  WM_DPICHANGED observable and fonts re-created.

### G1-M2: virtualized Apps page (elaborates NFR-07 + DEC-11 §2 "virtualized card lists")

- Replace the r1 cap-200-clip with TRUE virtualization: heap snapshot
  (grown on demand), custom-drawn scrollbar + WM_VSCROLL + mouse wheel,
  render ONLY the visible row window (frame < 16 ms at 5k rows is
  asserted by the M1 footprint check).
- Research grounding: LVS_OWNERDATA was evaluated and REJECTED because
  MS documents that grouping is unavailable in owner-data mode and
  LVM_SORTITEMS is unsupported there (list-view controls-overview) —
  and the shell is fully owner-drawn anyway (no ListView control).
  NOTE: the r1 research premise "upstream uses a virtual ListView" was
  corrected by the same research pass — upstream apps list is a classic
  grouped ListView with LVM_SORTITEMSEX; our card model supersedes it.
- Filter pipeline adopts the System Informer architecture (MIT,
  phlib/treenew.c + searchbox.c precedent): master index + filtered
  index arrays rebuilt on a debounced (~200 ms SearchDelayMs precedent)
  global search box — DEC-11 §1. The search edit is a native child
  themed dark via the vendored `_r_theme_initialize` subclass engine
  (its exact designed purpose).
- Idle discipline: the 2 s timer re-snapshots under the shared apps lock
  and compares a FULL-ROW signature (name+path+state per row) — the
  cheaper aggregate-signature idea (counts + first/last name) was
  rejected by the goldfish round (finding 6): it misses middle-row
  renames, allow↔prompt toggles, and swaps. Full-row hash is O(n) per
  tick — trivial at 5k rows; InvalidateRect fires ONLY on change. A
  module-side revision counter (O(1) tick, zero periodic lock
  contention) is recorded as a future optimization, not an M1
  requirement.
- The search box is SHELL-GLOBAL from M1 ("filtering the active page"
  per spec.md); since Apps is the only content page in M1, the M1
  filter binds to Apps, and per-page filter semantics extend with each
  page milestone (G-2/G-3) — stated explicitly so the spec-level claim
  is not read as deferred wholesale.
- AC-G-4 measurement note (goldfish finding 11): the r1 scaffold has no
  tray integration — M1 asserts the idle budget in the HIDDEN-WINDOW
  state; the tray surface itself follows design r2 §8 in the prompting
  milestone (M3).
- Resize re-enabled (thick frame + maximize): virtual scroll makes
  resize safe; WM_SIZE invalidates only (paint is double-buffered).

### G1-M3: RTL mirror decision (elaborates spec "RTL/Arabic mirror layout designed in M1")

- APPROVED approach: DRAW-SIDE manual mirroring (rail on the right,
  DT_RIGHT text, right-to-left chip order, MB_RTLREADING message boxes —
  all already in the r1 scaffold) — NOT WS_EX_LAYOUTRTL.
- Grounding: MS "Window Layout and Mirroring" documents the coordinate
  flips (GetWindowRect/ScreenToClient breakage → MapWindowPoints
  near/far semantics), automatic bitmap mirroring, and per-dialog
  opt-in — hazards that a fully custom-drawn surface with its own
  hit-test rects does not need to take on. Precedents: TinyWall applies
  RTL per control/window (never process-wide); Notepad++ sets
  WS_EX_LAYOUTRTL explicitly per window it creates and pairs it with
  MB_RTLREADING for message boxes — the process-wide
  SetProcessDefaultLayout is documented as insufficient (owned windows,
  dialogs, message boxes excluded).
- Native child controls (the M1 search edit) receive explicit per-window
  treatment when introduced. This records the M1 RTL design the spec
  requires — designed in, not retrofitted.
- (r3 integration, goldfish finding 12) RAIL SIDE IS LANGUAGE-
  CONDITIONAL: DEC-11 §1 says "left navigation rail" (LTR phrasing);
  mockup-r1.html is dir="rtl" and renders the rail on the inline-start
  (= right). The shell follows the ACTIVE LANGUAGE DIRECTION: rail on
  the right under RTL packs (Arabic — the M1 default per the mockup),
  on the left under LTR packs. M1 implements the RTL side + the
  direction flag plumbing; the LTR side lands with the M4 i18n sweep.

### G1-M4: i18n day-one (NFR-05 compliance fix on the r1 scaffold)

- FINDING: the r1 scaffold hard-codes Arabic UTF-8 literals, violating
  the spec's "every string localized from day one". FIX: all shell
  strings route through `_r_locale_getstring` — the existing pipeline
  (STRINGTABLE fallback + bin/i18n INI packs; 29 language packs + an
  example template ship; missing keys fall back to English per routine
  behavior).
- (r3 integration, goldfish Q1 refinement) FORK-OWNED STRINGTABLE:
  strings live in src/gui/composite_shell_strings.rc +
  src/gui/composite_shell_res.h (IDS_SHELL_* from 305 — NOT 292: CVTRES
  packs STRINGTABLE resources in 16-id blocks as ((id-1)/16)+1, so
  upstream's 289-291 occupy block 19 (ids 289-304) and a fork block
  must start at the next free boundary; proven by the CVT1100
  duplicate-resource error on the first build, fixed by the +13 shift) wired via one
  ResourceCompile entry in the vcxproj. STRINGTABLEs merge across .rc
  files into the exe, and the routine fallback loader reads exe
  resources regardless of which .rc defined them — ZERO edits to
  upstream resource.h/resource.rc (a strictly better DEC-09 outcome
  than the append-only block the amendment originally proposed).
  Arabic.ini gains the IDS_SHELL_* keys in its [Arabic] section (the
  INI is keyed by symbolic IDS name, matching the existing file
  format); other packs fall back until translated (M4 sweep).
- Copy semantics: `_r_locale_getstring` returns the buffer of a
  temporarily-referenced object (routine rapp.c — the function's own
  TODO admits it) — callers copy immediately (upstream precedent,
  main.c:85), never store the pointer.
- (r3 integration, goldfish finding 1) FRESH-PROFILE SAFETY: locale
  resource/default names are populated only by the standard init
  sequence — the r1 pre-init `-gui` dispatch would make every
  localized string NULL on a fresh profile. FIX: delete the dead
  pre-init `-gui` block in main.c so the post-`_r_app_initialize`
  dispatch becomes the live path (the shell header's contract then
  holds verbatim), and call `_r_app_initialize_dll()` there as well so
  the shell of a hardened security tool keeps its safe-search/
  mitigation hardening (goldfish finding 10). Verification case added
  below: fresh profile directory + `-gui` → strings resolve.

### G1-M5: scaffold hygiene (r1 corrections, no key impact)

- Remove the TEMP SEH crash-writer (`_app_shell_seh_filter`) — its own
  comment marks it remove-after-diagnosis; the profile-init AV was
  fixed 2026-11-18 (4-dump root cause, ledger row 42). (goldfish
  finding 8 additionally pins two latent defects in it —
  `_snprintf_s` −1 cast to DWORD, x64-only CONTEXT fields breaking the
  Win32/ARM64 configs — reinforcing removal now.)
- (r3 integration, goldfish finding 3) LOCKDOWN PRE-FLIGHT IS G-1
  SCOPE — the r1 button bypasses DEC-04: it calls
  `_app_lockdown_enable (TRUE)` unconditionally, which defeats the
  module's own confirm gates, and never calls the dedicated
  `_app_lockdown_preflight` query API that composite_lockdown.h
  documents as existing precisely for this page. FIX: engage flow
  becomes verify-then-commit end-to-end — call
  `_app_lockdown_preflight()`, surface its outcome in the confirm
  dialog BEFORE committing, and only then pass is_confirmed=TRUE. The
  release flow keeps its confirm dialog. AC-G-5 then holds on the
  page as shipped, not after G-2.
- (r3 integration, goldfish findings 4/7/9) BUILD + CODE HYGIENE:
  duplicate ClCompile entry for composite_shell.c in the vcxproj
  (plain + /utf-8) collapses to the /utf-8 one (MSB3105 otherwise);
  the duplicated composite_shell.h include in main.c (lines 15/17,
  stale merged comment) collapses to one; `MSG msg = {0;}` replaces
  the WM_QUIT-silencing hack.
- Keyboard traversal (design Verification M1): arrow keys move rail
  selection, Enter activates; documented as WM_KEYDOWN handling.
- The Packs page keeps its 3 hard-coded ids for now — G-2 replaces them
  with the packs enumerator per the DEC-11 query-API contract (out of
  G-1 scope; flagged honestly in the page subtitle).

### G1-M6: basic accessibility stays in M1 (approved design line — no deferral)

- (r3 integration, goldfish finding 5 = owner-decision escalation) The
  r3 draft had silently reassigned "basic screen-reader labels in M1"
  (design r2 risks + Verification, verbatim) to the G-5 procedure — a
  scope slip on an approved owner-facing line. RESOLVED BY IMPLEMENTING
  IN M1 (the reviewer's sanctioned option A; no owner sign-off needed):
  - keyboard traversal + a drawn focus indicator on the rail (the
    focus model screen readers follow);
  - an MSAA IAccessible root for the shell window (oleacc/ole32 —
    system libraries, NFR-02-compliant; pure C vtable in
    src/gui/composite_shell_a11y.c) exposing accName for the 6 rail
    entries and the rendered app cards — the "rail and cards" labels
    the design names;
  - window text carries the product identity (already does).
  The FULL accessibility audit remains a later milestone exactly as the
  approved design states ("basic labels in M1, full audit later").

### Goldfish round 2 record (r3 integration, 2026-11-19)

- VERDICT: APPROVE-WITH-CHANGES. All three vendor-API claims verified
  true against routine source (copy-immediately contract incl. the
  in-source TODO, attr-20/attr-19 DWM fallback gated RS5, registry
  dark-mode detection). Blocking findings 1 (-gui dead dispatch breaks
  fresh-profile i18n), 2 (no DPI awareness → WM_DPICHANGED dead),
  3 (Lockdown bypasses DEC-04 pre-flight), 4 (duplicate ClCompile →
  MSB3105) integrated above; finding 5 resolved by in-M1
  implementation (G1-M6); finding 6 (signature widening) integrated in
  G1-M2; findings 7-13 (non-blocking) integrated where named.
  Reviewer-confirmed correct and NOT churned: IAT-hook rejection,
  draw-side mirroring, LVS_OWNERDATA rejection, buffered paint,
  resize re-enable, DEC-09 fork-owned .rc framing, milestone
  discipline. G-1 stays rail+theme+Apps per tasks.md; the pack hard-coded ids are honestly flagged for G-2 rather than silently kept.

### Post-review implementation record (2026-11-19)- The goldfish finding-3 fix exposed that the DEC-11 query-API contract
  `_app_lockdown_preflight` was HEADER-ONLY (declared 2026-11-18 for the
  arena implementers, never implemented — the linker caught it). Now
  implemented read-only in composite_lockdown.c mirroring the enable
  refusal gates (already-engaged / policy / engine-down / audit), plus
  the additive `_app_audit_probe` in composite_audit.c (read-only probe
  of the two audit refuse conditions — corrupt sidecar SEC-03 and
  subcategory query failure — because `_app_audit_enable` itself
  mutates and could NOT be called from a pre-flight).
- CVT1100 block-packing catch (above) — the r3 draft's "292" was
  corrected to 305 by the build itself (an empirical arbiter of the
  cheapest kind).
- Local build: x64 Release 0 errors / 0 warnings in all fork files
  (toolset v143 override — v145 is the CI runner's toolset; SAC blocks
  local execution of fresh dev builds per the standing posture, so the
  runtime verdict belongs to CI + the owner's interactive round).

---

## r4 amendment (2026-11-19): G-2 pages mechanics — external-research grounded

> Same protocol as r3: owner directive "continue the rest, always
> research what is published (المنشور), the methods, and the solutions".
> Second research pass (subagent, shipped docs/changelog/issues + primary
> source of simplewall upstream / portmaster-ui / WFN / pi-hole web).
> Every delta elaborates approved keys (DEC-11 query-API contract,
> FR-15, NFR-05, NFR-07) — no architecture change.
>
> HEADLINE FINDING: NO shipped firewall product displays countdown
> firewall rules — Portmaster's temporary-allow request (#2226) was
> CLOSED as not planned (2026-10-26), NetLimiter ships schedule windows
> not countdowns, TinyWall ships mode-scoped exceptions without timers,
> GlassWire ships nothing timed. The ONLY shipped per-rule timer in the
> product family is simplewall upstream itself (timer_array 2min..24h,
> threadpool expiry, remaining-time in TOOLTIP ONLY via
> _r_format_interval = StrFromTimeIntervalW). Our G-2 session-decisions
> surface therefore DEFINES the pattern, grounded in published
> countdown-display guidance (see G2-M4).

### G2-M1: the DEC-11 query-API contract becomes REAL (measured: header-only)

- Measurement result (the G-1 lesson generalized): of the six declared
  enumerators, ONLY `_app_state_querycount` existed. G-2 implements,
  READ-ONLY, exactly the declared signatures — no contract edits:
  - `_app_state_query` (index → app_hash, name, is_block, is_once,
    remaining_seconds): the decision struct has NO name field — the
    name resolves from apps_table by app_hash (verified: profile.c
    keys apps_table by _r_str_gethash(path) and the publisher module
    hashes the identical string). LOCK COMPOSITION (r3 goldfish
    correction — the r4 draft's apps-outer claim was FALSE: the
    prompting path nests NOTHING, an opposite state→apps edge EXISTS
    in _app_state_applyall via _app_getappitem, and the vendor queued
    lock is writer-priority so the pre-existing edge map carried a
    latent ABBA): the query takes lock_state ALONE — snapshot
    {app_hash, is_block, is_once, expires} under a generation counter
    (bumped on every decision mutation: decide / revoke / expiry
    callback / clearfilters), release, then resolve names per hash via
    `_app_getappitem` (referenced return, its own internal apps lock,
    ZERO nesting — mirrors the G-1 shell pattern). remaining =
    expires ? max(0, expires - now) : 0 (0 = until restart, per
    contract). SAME-MILESTONE MANDATED FIX (r3 finding 1):
    `_app_state_applyall`'s in-lock `_app_getappitem` nesting is
    REMOVED — restructured to hash-snapshot under lock_state →
    apps resolution outside every lock → redeploy under a shared
    re-acquire (re-finding each decision, skipping expired/removed
    ones). This kills the ONLY state→apps edge; the remaining
    apps→state edges become cycle-free. (r3 finding 10, non-blocking,
    recorded as backlog: the pre-existing expiry-callback and deploy
    WFP-UI-under-lock paths are the P1-1 shape on NON-UI threads —
    real, but out of G-2 surgical scope.)
  - `_app_packs_querycount/_app_packs_query` (id, version, enabled):
    the enabled-pack store IS the packstate sidecar
    (composite_packstate.json; entries carry pack_id + version +
    rules_hash + deployed-GUID array — every entry passed hash-verify
    by construction, DATA-02). Parsed ONCE per sidecar mtime into a
    lock_packs-protected snapshot (the inventory-once precedent from
    the composite audit goldfish round); per-row file reads rejected.
  - `_app_publisher_queryanchorcount/_app_publisher_queryanchor` (name,
    path_count, is_valid): publisher_anchors = hash-of-hex →
    {signer_hash, signer_name}; path_count = scan of publisher_paths
    matching the anchor's signer_hash (small table, lock_publisher
    shared). VALIDITY SEMANTICS (r3 goldfish correction: invalidation
    NULLs signer_hash, so invalid paths silently UNLINK from their
    anchor and "red" would be unreachable — the exact silent-green the
    r4 draft forbade): the module's invalidation sites now RETAIN
    signer_hash on invalidated paths (safe — every deploy/bind path
    already gates on is_valid; the struct comment is updated to match),
    and the query renders: Valid = ≥1 matching path AND all valid AND
    none stale; Invalid = any matching path with is_valid FALSE (the
    revoked-class red, now reachable); Not-checked/Unknown = zero
    matching paths OR any member with mtime != validated_mtime (the
    free conservative staleness signal, r3 finding 7) — gray, never a
    silent green.
  - Lockdown gains NO new API in G-2 (its page is functional since
    G-1; the mockup's live survival-rule panel needs a snapshot API
    that is NOT in the declared contract — deferred, honestly
    subtitled).

### G2-M2: Rules page = two separated sections (NetLimiter precedent: activity vs rules are separate views)

- Section 1 SESSION DECISIONS: rows = verdict dot + text label (ALWAYS
  paired — WCAG: never color alone; ~8% of male users cannot reliably
  distinguish red/green) + app name + countdown. Verdict colors adopt
  the shipped Portmaster map: allow = green, block = red. EXPIRED
  STATE DROPPED (r3 goldfish correction: the module's expiry timer
  REMOVES AND FREES the decision at expiry — no later cleanup exists —
  so an "expired gray" row is unsatisfiable via the query API): the
  row disappears at the next 1s tick; expired-history is the Log
  page's surface (G-3, ledger rows), not a live row.
- Section 2 PUBLISHER ANCHORS: rows = "Verified publisher: <signer>"
  (the UAC phrase users already trust; unsigned/unknown → "Unknown
  publisher" per the same Windows vocabulary) + "(n filters)" path
  count + validity in the shipped 4-state PKI language (union of
  Chrome/Firefox/Kleopatra/Pi-hole): Valid = green check; Invalid/
  revoked-class = red + "Rules from this anchor are no longer trusted"
  hard-fail framing (browsers remove the bypass for revoked certs —
  our invalid anchor faces match); Unknown/not-checked = gray.
  Group headers carry counts, upstream pattern "(n/total)".
- Permanent rules remain upstream's editor surface (NFR-01 re-home) —
  the G-2 page does not duplicate upstream's rules tabs (DEC-09:
  pull, not duplicate).

### G2-M3: Packs page = the sidecar snapshot, canonical columns synthesized from uBO + Pi-hole + Portmaster

- Replaces the G-1 3-hard-coded placeholder rows (which were honestly
  flagged as placeholders). Row = enabled pill | pack name "(id)" |
  version pair (epoch-aware rendering follows the Pi-hole
  relative+absolute date-pair pattern) | deployed-filter count from
  the sidecar GUID array ("n filters") | health dot.
- HEALTH WORDING (r3 goldfish correction: the sidecar trailer is
  FNV1a-32 — tamper-EVIDENT, not cryptographic; ECDSA fires at pack
  import only): the pill reads "in store (checksum ok)" — never
  "verified". Health vocabulary = Pi-hole's 5-level colors mapped
  onto our truth: sidecar entries = green; a pack file in the cache
  dir NOT in the store = gray "not enabled"; signature-failed = red,
  sourced from apply-time logs (the store can never contain it —
  corrupt stores are never rewritten).
- NO TOGGLE IN G-2 (r3 finding 9): `_app_packs_enable` is DEC-11
  prose but NOT a declared query-API signature — the declared
  contract carries only the two read-only enumerators, so toggling
  waits for its own contract addition. The page carries the G-1
  honesty subtitle, extended: epoch/watermark columns and the import
  wizard entry point are CONTRACT-DEFERRED (DEC-11 prose wants them;
  the declared signatures do not carry them) — both flagged on the
  page, not silently omitted.

### G2-M4: countdown display rule (the published-guidance synthesis)

- Adaptive precision, text-first, tabular numerals (digits must not
  shift): >60m → "3h 05m" (60s cadence) · 10-60m → "42m" (30s) ·
  1-10m → "4m 38s" (1s cadence, the urgency window — per-second text
  is the OTP/Chrome precedent where windows are short) · ≤60s → "38s"
  with red under 10s (Authenticator ring semantics) · "until restart"
  = static badge (Portmaster #2226 community wording + upstream v3.2
  "until reboot" lineage).
- Tooltip (and a11y name) always carries absolute + relative:
  "Expires 16:42 (3h 05m)" — the UX.SE/Prototypr pairing rule.
- Machinery: remaining computed from the stored absolute expiry
  (upstream's ptr_app->timer pattern — never ticking accumulation);
  ONE 1-second shell timer active only while a countdown row is
  visible, invalidating ONLY rows whose displayed string changed
  (NN/g 0.1-1-10s response limits justify cheap per-second redraws
  in owner-drawn cells, never whole-list repaints). The actual expiry
  state flip remains the module's threadpool timer (state.c htimer).
- TIMER COMPOSITION RULES (r3 finding 5): (i) the G-1 2s full-row
  signature EXCLUDES countdown text (it hashes the apps snapshot, not
  the rules rows — the two surfaces stay orthogonal, or every 2s tick
  would report "changed" and violate the never-whole-list-repaint
  budget); (ii) the 1s timer is killed on page-leave and whenever no
  countdown row is visible; (iii) countdown-row invalidation is owned
  EXCLUSIVELY by the 1s tick with a per-row last-displayed-string
  cache. Both timers are GUI-thread WM_TIMERs — no race; InvalidateRect
  coalesces.

### G2-M5: publisher badge wording

- Display: "Verified publisher: <signer_name>" (signer_name = the
  upstream CN extraction, informational per module docs). The
  O-preferred form (UAC renders Organization when present) needs a
  CertGetNameStringW extension to upstream's `_app_verifygetstring`
  — an upstream-file change, deferred out of G-2 scope with this
  record (DEC-09 rebase-cheap rule).

### G2-M6: a11y continues (G1-M6 pattern)

- Every new row type exposes accName = humanized line (verdict label +
  name + countdown text; anchor name + validity label; pack name +
  version + filter count). Countdown rows include the absolute time.

### i18n (NFR-05)

- New IDS_SHELL_* block starts at 369 (the G-1 lesson: 305-359 occupies
  blocks 20-23; the next FREE block boundary after 359 is 369). English
  in composite_shell_strings.rc + Arabic.ini keys, same pipeline.

### r4 verification additions (M2, r3-corrected)

- Session countdown: seeded decision at 2min renders "2m 00s"→"1m 59s"
  (1s cadence); at expiry the row DISAPPEARS at the next tick (the
  module's timer removes the decision — no gray state exists).
- Anchor with one invalid path renders red + hard-fail copy (never
  green) — reachable because invalidation now RETAINS signer_hash.
- Anchor with any member whose mtime != validated_mtime renders
  gray "not checked recently" (never green).
- Packs page shows exactly the packstate entries; a hand-corrupted
  sidecar renders the fail-closed state (empty + honest subtitle), not
  fabricated rows; an unreadable sidecar (sharing-violation window)
  keeps the previous snapshot and retries — it does not poison the
  fail-closed state.
- Lock-order regression: the Rules page enumerates while a prompt is
  pending without deadlock — the query takes lock_state ALONE and
  applyall no longer nests apps inside state (the only state→apps
  edge removed; re-checked by code inspection).
- Contract hygiene: the duplicate `_app_state_querycount` declaration
  in composite_state.h collapses to one (r3 finding 4).

### r3 integration record (2026-11-19, goldfish round 3)

- VERDICT: APPROVE-WITH-CHANGES. Blocking findings 1 (lock-order
  claim false; applyall carries the only state→apps edge), 2 (anchor
  red unreachable — invalidation NULLs signer_hash), 3 (expired-gray
  unsatisfiable — expiry removes+frees) integrated above as text
  corrections + same-milestone code mandates. Non-blocking 4 (dup
  decl collapse), 5 (timer composition rules), 6 (mtime snapshot
  cautions: stat-without-open; unreadable = keep-previous), 7
  (staleness signal adopted), 8 (health wording), 9 (deferral
  subtitles + no-toggle), 10 (expiry-callback P1-1 shape → backlog)
  integrated. Verified correct and NOT churned: header-only
  measurement exact; all six signatures implementable with NO
  contract edits; apps_table keying verified (path_hash == app_hash);
  packs/publisher single-lock compositions cannot deadlock; CVTRES
  block math for 369 independently confirmed; FR-15 1:1 coverage
  holds for G-2 scope.

### Research citation registry (r4)

- simplewall upstream src/{global.h,timer.c,controls.c,helper.c,
  notifications.c} + CHANGELOG v3.0.8-v3.9 (timer_array, IDS_TIMELEFT
  tooltip-only, _r_format_interval = StrFromTimeIntervalW, CN-only
  signer string, IsOCSPEnabled revoke gate)
- Portmaster #2226 (closed not-planned 2026-10-26) + portmaster-ui
  _verdict.scss verdict color map + conn-row.html + filter-list.html +
  app-view.html (no publisher surface shipped)
- WFN Console/UI/Pages/Rules.xaml (the permanent-rules column set)
- pi-hole/web groups-lists.js + pi-hole.css (5-level health colors
  with exact hexes; relative+absolute date pairs)
- gorhill/uBlock wiki Dashboard: Filter lists (commit semantics,
  update-now gating, staleness affordance)
- NetLimiter docs (activity vs rules separation; scheduler windows)
- Microsoft Authenticator FAQ + listing (ring countdown semantics);
  NN/g response-times-3-important-limits (per-second redraw budget);
  UX.SE 10238 + Prototypr (adaptive precision, absolute+relative)
- Microsoft Learn Authenticode + UAC "Verified publisher:" wording
  (O-else-CN derivation); Kleopatra T7321 + Gpg4win changelog (key
  validity visual language); Chrome ERR_CERT_REVOKED + Firefox
  SEC_ERROR_REVOKED_CERTIFICATE (revoked = no bypass); TLS alerts
  44/45 (revocation computed at validation, not stored)
- WCAG 3.0 + UX Planet red/green (never color alone)

### Research citation registry (r3)

- ysc3839/win32-darkmode DarkMode.h (ordinals 104/132/133/135/136;
  IAT-hook rejection rationale; ShouldAppsUseDarkMode ≥1903 issue#3)
- Notepad++ PowerEditor/src/DarkMode + NppDarkMode.cpp (buffered-paint
  architecture, per-window RTL styles, localization.cpp RTL="yes")
- learn.microsoft.com: list-view-controls-overview (ownerdata: no
  groups/no LVM_SORTITEMS), lvm-setitemcount, Window Features → Window
  Layout and Mirroring (MapWindowPoints, SetProcessDefaultLayout
  limits, MB_RTLREADING), dwmapi DWMWINDOWATTRIBUTE (attr 20 history),
  uxguide/win-dialog-box (specific commit buttons, safe defaults —
  feeds M3 prompt design, recorded not implemented in G-1)
- System Informer phlib/treenew.c + phlib/controls/searchbox.c (filter
  pipeline + SearchDelayMs debounce — architecture adopted, code NOT
  ported; MIT, attribution noted)
- TinyWall DarkModeCS.cs + Utils.cs (per-control RTL + dark-theme class
  map cross-check); WFN Notifier NotificationWindow.xaml.cs (Prev/Next
  queue + rule preview — recorded for M3); Portmaster
  service/firewall/prompt.go (binary prompt + bulk queue — recorded for
  M3; duration options remain an open Portmaster feature request #2226,
  confirming upstream simplewall's timer_array is already ahead)
- priv10 (DavidXanatos) = Limited Open Source License — structure
  reference ONLY, zero code reuse; GlassWire/NetLimiter closed-source —
  UX citation only.

### r3 verification additions (M1)

- Theme switch (dark↔light) repaints without flicker under resize
  (buffered paint asserted by eye + WM_PAINT count probe optional).
- 5k-row scroll smoothness at the NFR-07 frame budget (footprint job).
- Search debounce: typing 10 chars issues ONE filtered-index rebuild.
- No repaint when nothing changed (timer tick with identical signature).
- Keyboard: rail reachable and operable from the keyboard alone.
- (r3 integration) Fresh profile directory + `-gui`: every shell string
  resolves (the goldfish finding-1 regression case).
- (r3 integration) 150% display: WM_DPICHANGED delivered, fonts
  re-created, no stretched-bitmap text (goldfish finding-2 case).
- (r3 integration) Lockdown engage: pre-flight outcome visible in the
  confirm dialog BEFORE commit; a degraded pre-flight shows its specific
  condition (goldfish finding-3 case, AC-G-5).
- (r3 integration) Screen reader: rail entries and rendered cards expose
  names (Narrator basic pass) — the approved M1 line (G1-M6).

