# GUI plan

Implementation mandate: DEC-11 approved (owner, 2026-11-11) — this chain
implements the approved Option A architecture on the milestone sequence
below.

- Milestones per design r2: M1 shell+theme+Apps (usable replacement) ->
  M2 Rules/Packs/Lockdown pages -> M3 prompting redesign + Log page ->
  M4 i18n sweep + upstream dialog phase-out.
- Precondition: 2026-12-01 upstream rebase window lands FIRST (minimizes
  UI-file conflicts).
- UI code lives in fork-namespaced files (DEC-09 discipline).
- Verification: all Phase 1/2 probes + checklist stay green with the new
  shell; new UI procedures (theme/DPI, keyboard traversal, screen-reader
  labels, pack/lockdown flows); footprint job asserts budgets.

- DEC-04 (verify-then-commit) governs the Lockdown page: engage actions
  present the pre-flight outcome BEFORE committing, with the recorded
  rollback always available (mirrors the engine-side contract).
