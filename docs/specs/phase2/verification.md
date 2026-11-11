# Phase 2 verification record

- **2026-11-10/11**: implementation round executed test-first.
  - FR-07 zones: 24-case headless suite ALL PASSED (parse edge cases,
    coalesce/touch/contain/gap semantics, brute-force oracle with 2000
    random CIDR operations vs a bitmap, 2M-scale load + verdicts). The
    suite caught two real defects during iteration: /32 shift-by-32 UB
    (every bare IP opened a full range) and a merge-across-gap condition
    in insert.
  - FR-11 apply delta: 4-case headless suite ALL PASSED (identical sets,
    single add, swap, overflow fallback).
  - FR-10 ledger: implemented (composite_ledger.c); quarantine flows are
    runtime-lane items (owner interactive run) — static integrity probes
    cover the baseline tamper contract.
  - Full project build with all Phase 2 modules: 0 errors / 0 warnings.
  - Goldfish gate: exit 0 (run after every tasks.md change).
- **Wiring follow-ups (recorded, not hidden)**: P2-3b wfp.c delta
  execution; P2-2 config-dir ACL hardening; GPO-origin registry
  cross-check refinement.

- **2026-11-11**: P2-2 FR-12 ACL hardening implemented (composite_integrity.c:
  profile-dir DACL = SYSTEM + Administrators FULL, interactive user READ;
  GetSecurityDescriptorDacl documented form; non-fatal/non-elevated aware).
  x64 build 0/0. P2-3b wiring decision recorded in tasks.md: blind insertion
  into _wfp_filtersapply rejected (apply-path ownership + crash risk); the
  delivered contract (diff core + overflow fallback) stands as the wiring
  prerequisite.
