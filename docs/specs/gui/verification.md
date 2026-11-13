# GUI verification record

- **2026-11-11**: chain bootstrapped (design r2 approved, gate exit 0).
  No UI code exists yet — verification items below activate per
  milestone.
  - G-1 lane: theme/DPI switching procedure; keyboard traversal;
    screen-reader labels (basic).
  - G-2/G-3 lane: pack/lockdown end-to-end flows; decide actions close
    the FR-05 loop.
  - G-4 lane: i18n sweep + RTL mirror check.
  - Footprint: idle-to-tray ~20 MB budget + <= 8 MB installed (NFR-03/
    NFR-07 job).
  - Regression: full Phase 1/2 probe suite + verification-checklist must
    stay green with the new shell.
