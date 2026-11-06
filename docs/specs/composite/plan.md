# Implementation Plan: Composite Phase 1 (Trust-aware prompting, Lockdown, Packs)

Derived from `spec.md`; preserves the approved decisions (DEC-01..DEC-09)
and acknowledges every risk (RSK-01..RSK-08).

## Approach

- **Chassis discipline (DEC-01):** all new code is C in `src/`, compiled
  into the existing project; no new third-party dependencies — new system
  APIs arrive via the existing dynamic-resolve pattern (NFR-02), keeping
  the Win7+ degradation story of `src/log.c:294-391`.
- **Module layout (fork-namespaced per DEC-09 for cheap rebase):**
  - `src/composite_audit.c` — install-time audit subcategory enable +
    inventory (DATA-01), startup crash-residue consistency check,
    exact revert on disable/uninstall (SEC-03), via in-process
    `AuditQuerySystemPolicy`/`AuditSetSystemPolicy` (no auditpol.exe —
    SEC-05).
  - `src/composite_eventlog.c` — `EvtSubscribe` on channel "Security"
    (XPath EventID 5157), culture-invariant parsing of ReplacementStrings
    + `LayerRTID` direction ints, port-merge dedup, single-flight window
    with hard-default block, session-duration state, subscription-health
    monitoring driving the prompt-degradation state and automatic
    fallback to the existing FwpmNetEventSubscribe pipeline (FR-01,
    FR-04, FR-05, DEC-03; RSK-08 throttle lives here).
  - `src/composite_publisher.c` — WinVerifyTrust capture at prompt
    time, signer-hash anchor store, materialized path filters, lazy
    at-connection validation cached per path+mtime, drop-out on
    validation failure (FR-02, FR-03, SEC-02, DEC-05).
  - `src/composite_lockdown.c` — record/verify/survive/commit/rollback
    recipe exactly per DEC-04 step order; service-scoped survival rules;
    recorded-snapshot restore; keep-or-release uninstall hook;
    confirm-without-prompts path under GPO (FR-06, RSK-01).
  - `src/composite_packs.c` — pack.json schema parse, detached-signature
    verify against the embedded public key (BCrypt ECDSA P-256,
    reusing the Round-2 signature core pattern), `pack_watermarks.json`
    anti-rollback store, unit enable/disable/update with exact filter
    delta, sidecar hash-check (FR-08, SEC-01, DATA-02).
  - `src/composite_state.c` — namespaced sidecar IO (pack state,
    audit inventory) with hash-check-on-load (DATA-01, FR-08).
  - integration points: `src/notifications.c` prompt flow (existing
    queue reused), `src/wfp.c` filter application, `src/profile.c`
    untouched (v5 wire compatibility, DATA-01), tray/status surfaces in
    `src/main.c` mirroring the hardening degraded-state pattern.
- **Verification first:** the sandbox bench (tools/hardening-sandbox.wsb
  pattern) gains Phase 1 probe scripts implementing the handoff AC-1..AC-10
  automated items; manual procedures land in verification.md (OPS-04,
  NFR-06).
- **Packs repo (FR-09):** sibling repository `simplewall-packs` with
  schema docs, three starter packs, and CI build/sign/validate —
  publishes pack artifacts the app consumes via FR-08; key rotation
  runbook required before first release (RSK-07).

## Decisions preserved (any conflict stops work and returns to the owner)

- DEC-01 fork C chassis, no rewrite; amwall reference-only.
- DEC-02 user-space / no driver / no service; bandwidth observation only,
  pulled from upstream.
- DEC-03 5157-only audit-event pipeline + fallback + prompt-degradation
  state; 5156 success auditing rejected (machine-wide flood).
- DEC-04 Lockdown guarded recipe; recorded-snapshot rollback; seal
  arbitration contract (app sublayer outranks mpsvc while healthy).
- DEC-05 publisher rules = signer anchor + materialized path filters +
  lazy at-connection validation; AppID driver excluded.
- DEC-06 Phase 3 domain layer shape (untouched this round).
- DEC-07 licensing hygiene: code only from GPL-3-compatible sources with
  per-file audit; AGPL (minimalfirewall, safing/spn), unlicensed repos,
  GPL-2-only = ideas only.
- DEC-08 phase gating: this round consumes keys, never invents them;
  amendments need a design revision bump + owner approval.
- DEC-09 monthly upstream rebase; fork-namespaced files; pull overlapping
  upstream features.

## Risks acknowledged

- RSK-01 audit subcategory GPO-blockable/reversible — fallback +
  confirm-without-prompts path; revert per SEC-03. Owner: fork owner.
- RSK-02 upstream drift — DEC-09/OPS-03 monthly rebase. Owner: fork owner.
- RSK-03 AV/SmartScreen — Authenticode decision gate before first
  public release (GPG-only interim); wufix path stays flagged. Owner:
  fork owner.
- RSK-04 port-53 conflicts (Phase 3) — acknowledged, owned, not
  actionable this round. Owner: fork owner.
- RSK-05 multi-month scope — per-phase shipping; Phase 1 is a releasable
  delta. Owner: fork owner.
- RSK-06 managed-environment quarantine fights (Phase 2 with FR-10) —
  acknowledged, owned, not actionable this round. Owner: fork owner.
- RSK-07 elevated negation + pack key compromise — threat-model boundary
  + rotation runbook before first release. Owner: fork owner.
- RSK-08 5157 log volume under Lockdown — subscription throttle + log-
  sizing guidance. Owner: fork owner.
