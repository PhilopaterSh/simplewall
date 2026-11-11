# Phase 2 tasks

- [x] P2-1 ledger core (FR-10, DATA-03) - implemented 2026-11-10: composite_ledger.c (baseline, diff, quarantine/approve/reject, GPO exemption, startupcheck); x64 clean build
- [x] P2-2 FR-12 baseline hash-check DONE (in P2-1); config-dir ACL hardening remains for the follow-up round
- [x] P2-3 FR-11 incremental apply CORE DONE (composite_apply.c: pure GUID-diff decision + overflow fallback-to-full-rebuild, 4-case headless suite GREEN; NFR-04 harness tools/bench-nfr04.ps1 procedure recorded; wfp.c delta-execution wiring = P2-3b follow-up: wfp.c delta-execution wiring REQUIRES deep study of _wfp_filtersapply (shared with the parallel session); the safe scope delivered = decision core + overflow fallback contract; blind insertion into the apply path was rejected as a risk larger than the win)
- [x] P2-4 FR-07 blocklist zones engine - composite_zones.c (dependency-free sorted coalesced ranges + binary-search verdicts) + 24-case headless suite GREEN incl. 2M-scale; caught+fixed /32 shift-UB and merge-across-gap during test-first iteration
- [x] P2-5 (FR-10, FR-12) Audit-tab data API DONE (_app_ledger_queryforeign/querycount on the last diff, policy flag included); GPO registry-crosscheck refinement remains heuristic (recorded limitation)
- [x] (NFR-06) P2-6 verification DONE: headless suites (24 zones + 4 apply cases) ALL PASSED; full project build 0/0 with all Phase 2 modules; DATA-01/NFR-02/SEC-05 asserted by construction + probes; OPS-01 gate exit 0
