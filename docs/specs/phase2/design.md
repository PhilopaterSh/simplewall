# Phase 2 design (consumes design.md r5 keys unchanged — DEC-08)

> Owner approval recorded verbatim (2026-11-10 chat): "انا الان للوقت الحالي
> اريد اكمال كل المحتوي الي الخاص بال Backend الحالي". Umbrella:
> ../composite/design.md r5 (approved). This chain covers the Phase 2
> backend contracts only; the GUI is a separate chain (DEC-11 draft).

## Contracts in scope (verbatim keys from the umbrella)

- FR-07 sorted range arrays + binary search blocklist engine (2M/zone,
  32 zones, IPv4+IPv6, same verdicts).
- FR-10 audit ledger: WFAS baseline diff, quarantine approve/reject
  semantics, policy-managed rules reported never quarantined.
- FR-11 incremental filter apply (diff-based, transaction contract kept).
- FR-12 profile + derived-state integrity (ACL hardening, tamper-evident
  baseline, corrupt = refuse + rebuild from source of truth).
- DATA-03 ledger baseline: JSON of WFAS rule identities (name+hash),
  rebuildable.
- NFR-04 incremental apply p95 <= 1.1x full rebuild; unfiltered window
  strictly smaller.
- Inherited: NFR-02/03/05/06, DATA-01, SEC-05.

## Scope boundary decisions

- DEC-08 (inherited): Phase boundary per the umbrella — this chain
  implements the Phase 2 backend contracts; GUI (DEC-11 draft) is a
  separate future chain, not consumed here.
- DEC-11 (referenced): the GUI round is out of scope for this chain;
  the ledger/blocklist data APIs designed here are what the future GUI
  consumes.

## Architecture decisions (P2-level)

- P2-A: ledger module `composite_ledger.c/.h`, lockdown-pattern sidecar
  IO (magic + key=value + FNV1a trailer), quarantine via disable +
  marker suffix, approve strips marker exactly, reject persists identity
  so recreated rules re-flag.
- P2-B: incremental apply = desired-stream (rebuild-on-change planner,
  adopted 2026-11-10) diffed against live provider filter enumeration;
  add/remove deltas only; joined/own transaction pattern unchanged.
- P2-C: blocklist zones = sorted (start,end) UINT32 arrays + binary
  search; pack per-IP rules collapse into zone queries at the verdict
  path; IPv6 struct-ready in the same round, wired in the follow-up.
- P2-D: GPO origin heuristic finalized inside this chain (policy-store
  registry cross-check), replacing the Phase 1 placeholder.
