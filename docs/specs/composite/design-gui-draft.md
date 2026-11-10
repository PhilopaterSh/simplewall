# design-gui-draft — composite native GUI, r2 (DRAFT — owner approval pending; goldfish round 1 APPROVE-WITH-CHANGES integrated)

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
