# GUI handoff (chain adapter record)

> Consumes DEC-11 + FR-15 + NFR-07 (defined in design.md) + inherited
> keys verbatim. Owner approval recorded verbatim in design-gui-draft.md
> r2 header (2026-11-11).

## AC items (chain-level)

- AC-G-1 design fidelity: the shell implements Option A as approved
  (6-page rail, DEC-11) — verified by design-to-code review at each
  milestone, not by assumption.
- AC-G-2 coverage: every composite capability has a page (FR-15
  1:1 mapping asserted in spec.md).
- AC-G-3 zero regression: upstream editor re-homed (NFR-01); all
  Phase 1/2 probes + verification-checklist stay green with the new
  shell.
- AC-G-4 budgets: rendering frame < 16 ms at 5k rows, GDI handles
  < 10k, idle-to-tray ~20 MB (NFR-07, asserted by the footprint job).
- AC-G-5 safety: Lockdown page follows DEC-04 verify-then-commit; no
  machine-critical action from the UI bypasses the engine gates.
- AC-G-6 build + gate: x64 0/0, goldfish check exit 0 per milestone.

## Evidence

- Design r2: goldfish round 1 APPROVE-WITH-CHANGES — all changes
  integrated (honest query-API contract, editor re-home, batch-decide,
  perf/RTL/rebase risks).
- Gate: exit 0 (0 failures, 3 non-blocking orphan warnings).
- Implementation: G-1..G-5 pending milestone build (post-rebase window
  2026-12-01); this handoff records the chain contract ahead of the
  code, per the CI chain-gate requirement.
