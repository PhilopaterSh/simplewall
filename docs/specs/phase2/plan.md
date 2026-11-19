# Phase 2 plan

Scope boundary: per DEC-08 this chain covers only the Phase 2 backend
contracts; per DEC-11 the GUI is a separate future chain consuming the
data APIs designed here (it never re-opens this chain).

- Module: `src/composite_ledger.c/.h` (FR-10, FR-12, DATA-03). Reuses the
  lockdown sidecar IO pattern (magic + key=value lines + FNV1a trailer),
  INetFwPolicy2 C-COM enumeration (wfp.c pattern), and the warn-and-leave
  corrupt-sidecar contract.
- Quarantine rule representation: disabled WFAS rule with description
  suffix marker `simplewall-quarantine:<epoch>`; approve = re-enable +
  strip marker; reject = keep disabled + flag persists (baseline records
  rejected identity so re-created rules re-flag).
- GPO exemption: rules whose binary path hashes live under the Policies
  store are not enumerable via INetFwRules alone; heuristic = rule Name
  prefix policy convention + registry cross-check deferred to P2-5
  refinement (recorded limitation in Phase 1 of this chain).
- FR-11: the rebuild-on-change planner (quietwall arena round 4 design,
  adopted) emits the full desired stream; incremental apply diffs the
  live filter enumeration by our provider against the desired stream —
  add missing, remove stale, keep matching. Transactions per existing
  pattern. NFR-04 harness = tools/bench-nfr04.ps1 measuring apply wall
  time + unfiltered window via net-event sampling.
- FR-07: zone = sorted (start,end) UINT32 ranges, binary search verdict;
  loader streams CIDR text; IPv6 struct-ready (dual counters), applied to
  pack BLOCK rules by collapsing per-IP filters into zone queries at
  classify time — integration point = wfp.c verdict path, Phase 2 second
  task after ledger.
- Verification: extend tools/bench-phase1-probes.ps1 with ledger probes
  (baseline tamper, quarantine restore, GPO exemption); goldfish check
  gate before any merge.

## Cross-cutting keys honored in every task

- DATA-01: every new sidecar (ledger baseline) is namespaced and never
  touches profile.xml (P2-1 implements it; P2-6 probes assert it).
- NFR-02: MSVC /W4 + /analyze clean, system libraries only
  (P2-1..P2-4 all build under the standing build recipe).
- SEC-05: no new processes/binaries — ledger and zones run inside the
  existing single-binary elevation model (asserted in P2-6).
- NFR-06: automated tests runnable without elevation = the bench probes
  (P2-6 records them; gate runs local pre-merge (OPS-01 lives in the composite chain; here the gate is the same tool, recorded per this chain's verification step)).
