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

- **2026-11-19**: G-1 IMPLEMENTED (r3-integrated; lane feat/gui-g1).
  - Build: x64 Release 0 errors / 0 warnings in all fork files (local
    toolset v143; v145 = CI). SAC blocks local execution (standing
    posture) — runtime verdict = CI runner + the owner's interactive
    round.
  - R3 verification additions landed as code: theme tri-state
    (IsShellLightTheme, auto-detect registry read), buffered paint,
    DPI awareness + WM_DPICHANGED font recreation, virtualized Apps
    page + custom scrollbar + debounced global search, full-row
    signature idle discipline, locale-pipeline strings (IDS_SHELL_*
    305-359 + Arabic.ini), draw-side RTL with the direction-flag
    plumbing, DEC-04 lockdown pre-flight surface
    (_app_lockdown_preflight + _app_audit_probe implemented read-only),
    rail keyboard traversal + MSAA labels (G1-M6), SEH debug writer
    removed.
  - Pending: the r3 verification additions list (fresh-profile i18n,
    150% DPI, preflight-outcome-then-commit, Narrator pass, 5k-row
    budget) runs in the CI/owner lane — locally blocked by SAC.
