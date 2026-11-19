# Goldfish Review #3 (full pass) — design.md r3

Reviewer: third fresh-context goldfish (read design r3 ONLY, standalone).
2026-11-06. **VERDICT: needs-revision (6 blocking, 6 suggestions)** — all
addressed in r4.

## Blocking (→ r4 fixes)

1. Journey 3 rollback wording ("rolls back to ALLOW") contradicted
   DEC-04/FR-06 recorded-snapshot fix; also verification-before-commit
   leaves nothing to roll back. → journey rewritten (record-verify-
   commit recipe; abort-before-commit).
2. FR-06 test asserted restoring state the design never defines
   ("previously-disabled user rules") AND DEC-04's "denies everything"
   over-claimed: specific WFAS allow rules outrank the default action.
   → Lockdown enable now records + disables the outbound-allow set
   (survival/app-own excluded), restored from the snapshot; "seal
   governs" wording replaces "denies everything".
3. Healthy-engine direction of the arbitration contract had no
   acceptance route (only degraded was tested). → healthy-direction
   sandbox bullet added (engine-permitted flows, engine-blocked stays).
4. "Removed engine" case untested + uninstall contradicted the backstop
   promise. → stopped-direction test bullet (terminate process); 
   uninstall-under-lockdown = keep-or-release, default release (journey
   6, DEC-04, SEC-03 qualified).
5. FR-10 registry path was WRONG (`Policies\WindowsFireWall\…` missing
   the `Microsoft` segment) and conflated GPO with MDM/CSP. → corrected
   GPO path + MDM heuristic deferred to phase spec; sandbox test now
   constructs a policy-store rule (constructible precondition).
6. Anti-rollback unsound: test had no precondition/water-mark storage,
   and FR-12's rebuild-from-source-of-truth could reset the water-mark
   (rollback completed by corruption). → DATA-02 pins high-water mark in
   pack-state sidecar; FR-12 stores marks apart from rebuildable state;
   lost marks ⇒ affected packs refuse until re-confirmed; FR-08 test
   gains its precondition.

## Suggestions (→ r4 fixes)

7. OPS-02 cert dependency unbounded → must be decided before first
   Phase 1 public release; GPG-only interim documented in RSK-03.
8. FR-02 test omitted the trusted-publisher tier → added.
9. SEC-05 "no new processes" vs auditpol.exe → in-process Audit* APIs
   declared; sandbox child-process watcher test added.
10. Vague budgets → FR-07: load ≤ 3 s, lookup p99 ≤ 10 µs, RSS ≤ 64 MB;
    NFR-04: p95(incremental) ≤ 1.1 × p95(full rebuild) back-to-back.
11. DEC-05 materialization ambiguity for updated binaries at new paths →
    lazy at-connection signer validation (cached per path+mtime);
    match = materialize + permit (logged); mismatch = prompt.
12. RSK-07 mis-attribution (anti-rollback ≠ key-compromise mitigation;
    rotation is) → reworded; outcome 1 key list dropped FR-08; DEC-02
    bandwidth observation marked as outside composite key space.

**Mechanical checks after r4: zero orphan keys, zero invented keys.**
