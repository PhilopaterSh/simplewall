# Goldfish Review #4 (full pass) — design.md r4

Reviewer: fourth fresh-context goldfish (standalone read of r4 only).
2026-11-06. **VERDICT: needs-revision (6 blocking — 3 of them regressions
of r4's own partial fixes — + 8 suggestions)** — all addressed in r5.

## Blocking (→ r5 fixes)

1. [REGRESSION] Water-mark store defined in two contradictory places:
   DATA-02/FR-08 said "pack-state sidecar" while FR-12 said "apart from
   the rebuildable state" (whose rebuild would wipe a sidecar-resident
   mark). → r5: dedicated non-rebuildable `pack_watermarks.json`, named
   consistently in DATA-02/FR-08/FR-12 (row + test).
2. [REGRESSION] Degraded-direction test unexecutable: survival rules had
   no defined shape; a service-scoped rule can never pass a standalone
   probe, a port-scoped one dissolves the seal. → r5: survival rules
   defined as service-scoped (svchost + Dhcp/CryptSvc + WSL/ICS);
   automated lane asserts rule shape + continued denial; functional
   DHCP/CryptSvc continuity moved to the manual lane. CryptoSvc→CryptSvc.
3. Post-commit rollback never exercised (the cited bullet tested only
   the vacuous pre-commit abort). → r5: pre-commit-abort bullet renamed
   as such + new post-commit bullet (mid-step-(5) failure → full
   recorded-snapshot restore).
4. FR-07 load config ambiguous ("2M/32 zones" read as 2M total = 32×
   below the per-zone claim). → r5: 32 zones × 2M entries (64M total),
   budgets restated (≤30 s load, p99 ≤10 µs, ≤128 MB RSS).
5. NFR-04's "unfiltered window strictly smaller" had no route. → r5:
   window defined (apply-transaction wall time where effective ≠ target
   policy) + asserted in the same back-to-back run, zero full-teardown
   applies in steady state.
6. Orphan keys DEC-01, RSK-02, RSK-05 → wired into Problem/in-scope,
   DEC-09, outcome preamble.

## Suggestions (→ r5 fixes)

7. Lockdown refused under GPO-blocked audit → explicit logged
   confirm-without-prompts path (DEC-04, journey 3, RSK-01).
8. Missing risk: 5157 storm under Lockdown → new RSK-08 (dedup/throttle
   + log-sizing guidance; failure degrades to Windows' own audit
   behavior).
9. Quarantine reject semantics undefined → FR-10 row: reject = kept
   disabled + flagged; deletion separate; recreation re-flagged.
10. FR-05 burst test pin: 40 distinct probe processes.
11. NFR-06 gate parked in manual lane + OPS-01 assumed CI the fork
    doesn't have → unified convention: CI when available, else required
    local pre-merge recorded in verification.md (OPS-01/NFR-06 rows +
    manual-lane line).
12. NFR-02 froze Phase 1 link set while Phase 3 adds libs → "system
    libraries only, via the established dynamic-resolve pattern".
13. FR-11 measurement drift (in-session vs recorded baseline) →
    same-session back-to-back declared authoritative in bullet + row.
14. SEC-03 revert depends on an inventory with no home/loss story →
    audit-policy inventory added to DATA-01; loss downgrades to
    warn-and-leave (SEC-03 row).

**Mechanical checks after r5: zero orphan keys, zero invented keys; all
r5 spot-checks present.**
