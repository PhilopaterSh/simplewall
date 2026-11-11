# Phase 3 handoff (chain adapter record)

> Consumes FR-13/FR-14/SEC-04/DATA-04 + inherited keys verbatim
> (see design.md "Inherited keys"). Owner approval recorded verbatim in
> design.md header (2026-11-11).

## AC items (chain-level)

- AC-P3-1 cache: upsert/lookup with DATA-04 clamp (17 s floor, 86400 s
  ceiling), stale grace 60 s, hard eviction past grace — proven headless.
- AC-P3-2 chains: CNAME links to depth 8 with a cycle-safe walk;
  resolveip reports the terminal domain.
- AC-P3-3 both families: A (IPv4) and AAAA (IPv6) entries coexist;
  resolveip never crosses families.
- AC-P3-4 capacity: 64k entries LRU-evicted (never-touched oldest first);
  heap-lazy storage (NFR-03: zero static bloat).
- AC-P3-5 resolver safety: snapshot-before-write (FNV1a-validated
  sidecar), verify-then-commit gate, is_confirmed machine-write gate,
  exact revert refusing corrupt/missing snapshots, restart restore
  honoring the never-leave-DNS-broken invariant.
- AC-P3-6 build + gate: x64 0/0, goldfish check exit 0.

## Evidence

- Headless suite: tests/test_dnscache.c — 17/17 ALL PASSED (fake clock).
- Full project build with all Phase 2+3 modules: 0 errors / 0 warnings.
- Goldfish gate: exit 0 (re-run after every tasks.md change).
