# Goldfish Delta Review — design.md r2 vs review-r1.md

Reviewer: second fresh-context goldfish (read design r2 + review-r1.md only).
2026-11-06. Result: **all 8 blocking and all 12 suggestions from r1
verified RESOLVED in the r2 text** (substantively, not just claimed).

## New blocking introduced by r2 edits (→ fixed in r3)

1. **NEW-BLOCKING-1** — DEC-04's arbitration contract (degraded/removed
   engine → WFAS seal still denies; survival-rule efficacy) had no
   acceptance route; FR-06 bullet covered only rollback. Fixed in r3:
   sandbox arbitration test added (degraded-engine seal + DHCP/CryptoSvc
   survival probes + exact-state restore).
2. **NEW-BLOCKING-2** — DATA-02/RSK-07 anti-rollback had no acceptance
   route. Fixed in r3: anti-rollback test added to FR-08 bullet
   (older-version correctly-signed pack → refused + logged).

## Non-blocking notes from delta review (→ incorporated in r3)

- "Policy-managed" undefined → r3 adds registry-origin detection contract
  in FR-10 (policy store vs local store; finalized in phase spec).
- DEC-04 rollback assumed prior default was ALLOW → r3 records
  pre-lockdown per-profile defaults at enable and restores those.
- RSK-03's Authenticode mitigation conditional on certificate acquisition
  → already surfaced as open question; left honest.

**VERDICT (r2): needs-revision (2 blocking)** — both addressed in r3;
r3's additions are acceptance-bullets and definitions inside lanes the
delta review already audited, re-verified mechanically (orphan/invented
key check clean).
