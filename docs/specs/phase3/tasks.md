# Phase 3 tasks

- [x] T031 DNS cache core (FR-13, DATA-04, SEC-05, NFR-06) - implemented 2026-11-11: composite_dnscache.c (dependency-free, injected clock, TTL clamp 17/86400, stale grace 60s, CNAME chains depth 8, 64k LRU, A+AAAA); 17-case headless suite ALL PASSED; heap-lazy storage (NFR-03 clean)
- [ ] T032 ETW DNS attribution session (FR-13) — requires owner approval of the design before implementation (EGM)
- [ ] T033 (FR-13, SEC-03, DEC-04, DEC-06, RSK-04) resolver ownership SAFETY machinery: snapshot /
      verify-then-commit / exact revert / crash-residue check /
      resolver-death watchdog / per-interface opt-in / RSK-04
      port-53 conflict reporting — approval gate applies
- [ ] T033b (FR-13, DEC-06, RSK-04) bypass detection: cache-miss vs owned-resolver
      port comparison + external-resolver connection flagging —
      approval gate applies
- [ ] T034 DoH/DoT upstream + leak-prevention rules-as-data (FR-14, FR-08) — same approval gate
- [ ] T035 verification + SEC-04 purge probe (NFR-06, OPS-01, SEC-05, NFR-02, NFR-03, NFR-05, DATA-01, FR-08)
