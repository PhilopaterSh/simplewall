# GUI tasks

- [x] G-1 (M1) shell scaffold: rail + theme engine + Apps page over the
      existing apps table (FR-15, NFR-07) [enabling] — IMPLEMENTED
      r3-integrated 2026-11-19 (research-grounded + goldfish round 2
      integrated; compile 0/0 local, runtime verdict = CI/owner lane;
      see design-gui-draft.md r3 + post-review record)
- [x] G-2 (M2) Rules/Packs/Lockdown pages over the query APIs (FR-15,
      DEC-11) — IMPLEMENTED r4-integrated 2026-11-19 (the six DEC-11
      enumerators became REAL code; Lockdown page was functional since
      G-1, its live survival-rule panel deferred honestly; see
      design-gui-draft.md r4 + r3-integration record)
- [x] G-3 (M3) prompting redesign + Log page with decide actions
      (FR-15, FR-05, NFR-01) — IMPLEMENTED 2026-11-20: the Log part in
      G-3/1 (held rows + decide); the prompt part completed by Phase 1
      (T003 tiers / T005 duration menus / T006 held counter) + the
      G-3/2 held-line in the notification header (design r2 §7) —
      design-complete
- [ ] G-4 (M4) i18n + RTL mirror + upstream dialog phase-out (NFR-05,
      DEC-09) — PARTIAL 2026-11-20: the direction flag is config-driven
      (IsShellRtl, the LTR side testable); the shell strings were
      localized at G-1 (day-one); REMAINING: the upstream dialog
      phase-out (DEFERRED until runtime verification - destructive)
      + any residual string sweep
- [ ] G-5 verification: regression + UI procedures + footprint budget
      (NFR-07, NFR-06, FR-15)
