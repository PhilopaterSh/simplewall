# GUI design (composite shell) — consumable pointer

> Owner approval recorded verbatim (2026-11-11): the owner replied
> "اكمل" to the DEC-11 approval request. Canonical architecture:
> ../composite/design-gui-draft.md r2 (DEC-11: own native Win32 UI,
> 6-page navigation rail, upstream editor re-homed, batch-decide
> actions, query-API contract). This file exists so the goldfish gate
> can bind the chain to the approved decisions.

## Keys defined for this chain

- DEC-11: own native Win32 GUI per design-gui-draft.md r2 Option A.
- FR-15 (new, this chain): the shell surfaces every composite capability
  through the module query APIs (packs enumeration, publisher anchors,
  state durations, lockdown pre-flight, ledger foreign records) — no
  capability ships UI-invisible.
- NFR-07 (new, this chain): owner-drawn pages hold a rendering budget
  (frame < 16 ms at 5k rows, GDI handles < 10k) and release page
  bitmaps on hide (idle-to-tray stays ~20 MB).

## Inherited keys (verbatim from ../composite/design.md r5)

- FR-05 single-flight prompting: one visible prompt, concurrent novel
  connections held at hard-default block and batch-logged (the Log page
  decide actions close this loop).
- NFR-01 zero UX regression on paths that never fail (the upstream
  editor is re-homed, never dropped).
- NFR-05 every new UI string ships localized through the existing i18n
  pipeline.
- NFR-06 every new module carries automated tests runnable without
  elevation; the gate must be green to merge.
- DEC-09 fork-namespacing: composite UI code lives in fork-namespaced
  files; upstream-overlapping features pulled not duplicated.
- DEC-04 verify-then-commit precedent governs Lockdown page actions.
