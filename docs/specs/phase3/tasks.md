# Phase 3 tasks

- [ ] T031 DNS cache core (FR-13, DATA-04, SEC-05, NFR-06)
- [ ] T032 ETW DNS attribution session (FR-13) — requires owner approval of the design before implementation (EGM)
- [ ] T033 resolver ownership SAFETY machinery (FR-13): snapshot /
      verify-then-commit / exact revert / crash-residue check /
      resolver-death watchdog / per-interface opt-in / RSK-04
      port-53 conflict reporting — approval gate applies
- [ ] T033b bypass detection (FR-13): cache-miss vs owned-resolver
      port comparison + external-resolver connection flagging —
      approval gate applies
- [ ] T034 DoH/DoT upstream + leak-prevention rules-as-data (FR-14, FR-08) — same approval gate
- [ ] T035 verification + SEC-04 purge probe (NFR-06, OPS-01, SEC-05, NFR-02, NFR-03, NFR-05, DATA-01, FR-08)
