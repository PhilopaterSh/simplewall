# Phase 2 chain — backend accountability & scale

> Owner approval (verbatim, 2026-11-10 chat): "انا الان للوقت الحالي اريد اكمال
> كل المحتوي الي الخاص بال Backend الحالي". Consumes design.md r5 keys
> unchanged (DEC-08). GUI (DEC-11 draft) is a separate chain; this chain is
> frontend-independent.

## Functional contracts (from design.md r5, unchanged)

- FR-07 blocklist engine: sorted range arrays + binary search; >=2M
  entries/zone, >=32 zones, IPv4+IPv6; same verdicts as the per-IP filter
  path on the internal pack.
- FR-10 audit ledger: WFAS rule store diffed against persisted baseline
  (DATA-03); foreign add/modify/delete surfaced; optional quarantine
  disables pending review — approve restores exactly, reject keeps
  disabled + flagged; policy-managed rules (GPO store) reported, never
  quarantined.
- FR-11 incremental filter apply: diff-based add/remove preserving the
  tri-state transaction contract.
- FR-12 integrity: config-dir ACL hardening; ledger baseline
  tamper-evident (hash-checked; corrupt = refuse + rebuild from source of
  truth); watermarks outside rebuild scope (done in Phase 1).

## Non-functional

- NFR-06: every new module carries automated tests runnable without
  elevation (the bench probes cover the ledger/zone modules).
- OPS-01: goldfish check runs as the local pre-merge gate for this chain
  and is recorded per verification step; a failing gate blocks merge.

- NFR-04: incremental apply p95 <= 1.1x full rebuild, unfiltered window
  strictly smaller.
- NFR-02/03/05/06 inherited.
- DATA-03: baseline = JSON of WFAS rule identities (name+hash),
  rebuildable.
- SEC-05: no new processes/binaries.

## Tasks

- [ ] P2-1 `composite_ledger.c`: baseline snapshot (DATA-03) via
      INetFwPolicy2 enumeration; tamper-evident sidecar (DATA-01
      namespaced); diff (add/modify/delete) with GPO-store exemption
      heuristic (policy path rules never quarantined); quarantine
      disable + exact restore on approve; config gate
      `IsCompositeLedgerEnabled`.
- [ ] P2-2 FR-12 integrity: config-directory ACL hardening (limited
      write access to the profile dir for non-elevated users) +
      baseline hash-check-on-load with refuse-and-rebuild-from-source
      semantics.
- [ ] P2-3 FR-11 incremental apply: reconcile current WFP filter set vs
      desired set (rebuild-on-change planner output) — add/remove deltas
      only, inside the existing transaction pattern; NFR-04 benchmark
      harness script.
- [ ] P2-4 FR-07 blocklist engine: sorted CIDR range arrays (start,end)
      + binary search verdict API, zone loader (2M/zone, 32 zones),
      IPv4 first (IPv6 ranges struct-ready); bench script loads the
      internal pack at scale and compares verdicts vs the filter path.
- [ ] P2-5 i18n + surfaces: Audit tab data API for the (future) GUI;
      localization keys.
- [ ] P2-6 verification: probes extended to ledger quarantine flows +
      NFR-04 numbers recorded.
