# Phase 3 tasks

- [x] T031 DNS cache core (FR-13, DATA-04, SEC-05, NFR-06) - implemented 2026-11-11: composite_dnscache.c (dependency-free, injected clock, TTL clamp 17/86400, stale grace 60s, CNAME chains depth 8, 64k LRU, A+AAAA); 17-case headless suite ALL PASSED; heap-lazy storage (NFR-03 clean)
- [x] T032 (FR-13) ETW DNS attribution session - controller side implemented 2026-11-11: composite_dnsetw.c (StartTraceW/EnableTraceEx2 on DNS-Client provider, in-process per SEC-05, leftover-session crash handling, config gate IsCompositeDnsAttributionEnabled default OFF, enrichment-only contract); consumer/parse side (TdhGetEventInformation -> cache upsert) lands with the live-testing round
- [x] T033 (FR-13, SEC-03, DEC-04, DEC-06, RSK-04) resolver ownership SAFETY machinery - implemented 2026-11-11: composite_resolver.c (registry-based per-interface NameServer snapshot w/ FNV1a trailer + hash validation, verify-then-commit gate, is_confirmed machine-write gate, exact revert refusing corrupt/missing snapshot, startupcheck restore-on-restart honoring the never-leave-DNS-broken invariant, RSK-04 refusal for policy-managed via lockdown constant reuse; x64 clean build); resolver-death watchdog + live-query verification = wired when the owned in-process resolver lands (T034 dependency) snapshot /
      verify-then-commit / exact revert / crash-residue check /
      resolver-death watchdog / per-interface opt-in / RSK-04
      port-53 conflict reporting — approval gate applies
 - [x] T033b (FR-13, DEC-06, RSK-04) bypass detection core - implemented 2026-11-11: composite_bypass.c (well-known public resolver endpoint registry, loopback/owned-resolver exemption, port-aware verdicts 53/853, pack-schema rules-as-data emission reusing FR-08; 15-case headless suite ALL PASSED); cache-miss vs owned-resolver
      port comparison + external-resolver connection flagging —
      approval gate applies
- [ ] T034 DoH/DoT upstream + leak-prevention rules-as-data (FR-14, FR-08) — same approval gate
- [ ] T035 verification + SEC-04 purge probe (NFR-06, OPS-01, SEC-05, NFR-02, NFR-03, NFR-05, DATA-01, FR-08)
