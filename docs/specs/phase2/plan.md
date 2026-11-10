# Phase 2 plan

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
