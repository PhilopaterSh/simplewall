# Phase 2 handoff (chain adapter record)

> Adapter from the approved umbrella design (composite/design.md r5) to
> this chain's contracts, mirroring the composite chain's 50-key splice
> pattern. Keys consumed unchanged: FR-07, FR-10, FR-11, FR-12, DATA-03,
> NFR-04 + inherited NFR-02/03/05/06, DATA-01, SEC-05, OPS-01.

## AC items (chain-level)

- AC-P2-1 ledger: baseline written + diff detects a foreign add +
  quarantine approve restores exactly; GPO-origin rules reported only.
- AC-P2-2 integrity: tampered baseline refused and rebuilt from the live
  store at startupcheck; ledger sidecar stays outside profile.xml.
- AC-P2-3 apply delta: diff core emits zero delta for identical sets,
  exact add/remove for changes, overflow flags the full-rebuild fallback.
- AC-P2-4 zones: parse/coalesce/verdict semantics proven headless
  (24-case suite) + 2M-scale load.
- AC-P2-5 data API: foreign records queryable for the Audit tab surface.
- AC-P2-6 build + gate: /W4 clean 0/0, goldfish check exit 0.

## Evidence

- Headless suites: tests/test_zones.c (24 PASS), tests/test_apply.c
  (4 PASS) — run without elevation (NFR-06).
- Full project build with all Phase 2 modules: 0 errors / 0 warnings
  (x64 Release, v143 toolset, OutDir mergetest to dodge a running exe).
- Goldfish gate: exit 0 on this chain (see verification.md).
