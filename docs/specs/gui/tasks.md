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
      localized at G-1 (day-one); the residual string sweep DONE:
      automated parity check (res.h defines vs .rc entries vs
      Arabic.ini keys vs code usage) = 73/73/73 zero gaps, zero
      duplicate ids; 8 dead G-1/G-2 scaffold ids retired
      (SUB_RULES/SUB_PACKS/PILL_ENABLED/PILL_DISABLED/RULES_LINE/
      EXPIRES_FMT/RULES_EMPTY/ANCHORS_EMPTY — unreferenced, misleading
      "placeholder" texts); the only drawn literals are the
      language-neutral ✓ glyph; 5 latent shell warnings surfaced by the
      resource rebuild fixed (scrollmax forward-decl C4013/C4142,
      missing composite_publisher.h include C4013 x2, unused btn
      C4101) = TRUE 0/0 build. REMAINING: the upstream dialog phase-out
      (DEFERRED until runtime verification - destructive)
- [x] G-5 verification: regression + UI procedures + footprint budget
      (NFR-07, NFR-06, FR-15) — RUNTIME-VERIFIED 2026-11-21 on the
      verifier lane (run 12 = 44860140693, fork head 8150f18e): chain
      gates + build + selftest (TOTAL: 0 failures, exit 0 — exit code
      IS the failure count) + gui-testdrive (8/8 shots: search, apps,
      rules, packs, lockdown, log, settings, settings-light) ALL GREEN.
      The lane (Ph.Sh-Subdomain sw-verifier.yml) exists because the
      fork's own Actions dispatch is repo-blocked (422 desync — see
      docs/specs/gui/runtime-judges.md). The verification journey found
      and fixed SIX root-cause classes (Findings 5/8/10 in
      testing-record.md): the borrowed-pointer UAF (freeze), the
      borrowed-finalstringbuilder dereference x5 (exit fastfail),
      byte/char confusion x5 writers, HeapReAlloc-NULL x4 grows +
      addhashtableitem's drop-update, the filter-line format mismatch,
      and NTFS mtime coarseness (mtime+SIZE key). The next signed
      release MUST carry these fixes (three were latent corruption in
      the released v3.9.4).
