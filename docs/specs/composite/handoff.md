# Handoff: Composite Phase 1 (Trust-aware prompting, Lockdown, Packs)

> Generated from `design.md` revision `2026-11-06-r5` (approved — see the
> design header for the recorded owner approval, 2026-11-06). This file
> is an adapter between the approved design and the phase chain, not a
> second specification. Phase scope per DEC-08: this handoff serves the
> Phase 1 implementation round; Phase 2/3 keys are carried as deferred
> contracts and must not be implemented by this round.

> Approved: design owner, 2026-11-06 (recorded verbatim in design.md r5 header).

## Problem and intended outcomes

Per design.md § Problem and intended outcomes: the fork's product lane is
the only combination of no-driver lightness + trust-aware prompting +
guarded Lockdown + signed community packs. Phase 1 delivers outcomes 1–2
of that section: trust-aware prompting and Lockdown (FR-01..FR-06,
DEC-03..DEC-05) and signed packs with their repository (FR-08, FR-09,
SEC-01). Observable completion signals: the Phase 1 journeys
(design.md § User journeys 1–4, 6–7) pass their acceptance criteria below;
`goldfish check` against the umbrella design exits 0.

## In scope and out of scope

Exactly the design's § In scope and out of scope, plus the DEC-08 phase
boundary: this round implements FR-01..FR-06, FR-08, FR-09 and their
dependent SEC/DATA/NFR/OPS keys only. FR-07/FR-10/FR-11/FR-12 (Phase 2)
and FR-13/FR-14 (Phase 3) are deferred contracts — recorded in spec.md,
never implemented here. Prohibited adjacent work stays prohibited
(kernel driver, Rust rewrite, UI toolkit swap, telemetry, DPI bundling).

## User journeys and behavior

Design.md § User journeys 1–4 and 6–7 are authoritative for this round
(publisher-binding prompt; single-flight under a 40-process burst;
guarded Lockdown with recorded-snapshot rollback; signed pack import;
audit-policy revert at uninstall; no new processes/elevation). Journey 5
(ledger) is Phase 2.

## Acceptance criteria

Given/When/Then, from the design's § Verification split (automated lane
runs in the sandbox bench per the hardening T016 companion pattern;
manual procedures are documented in the round's verification.md):

- **AC-1 (FR-01):** Given the audit subcategory enabled, When a probe
  binary is blocked by a WFAS rule, Then exactly one deduped prompt
  (ports merged) fires from the 5157 pipeline; When the subcategory is
  disabled mid-session, Then the fallback engages and the
  prompt-degradation state is surfaced.
- **AC-2 (FR-02):** Given an existing rule / wildcard-or-pack rule /
  already-materialized trusted publisher covers a connection, When it
  occurs, Then no prompt appears and the event is logged.
- **AC-3 (FR-03):** Given a signed binary prompts, When the user picks
  "Always for publisher", Then a signer-anchored rule is stored; after
  the binary moves paths, the lazy at-connection validation permits it
  (logged) without re-prompting; a self-signed binary never gets the
  option.
- **AC-4 (FR-04):** Given once/until-restart/always decisions, When
  taken, Then non-always decisions live only in session state (absent
  from profile.xml on disk).
- **AC-5 (FR-05):** Given a 40-connection burst from 40 distinct probe
  processes, When it arrives, Then exactly one prompt window shows and
  the other 39 hold at block, logged.
- **AC-6 (FR-06):** Given Lockdown enabled, When the engine is degraded
  (provider filters deleted) or the process is stopped, Then un-permitted
  probes are denied by the WFAS seal and service-scoped survival rules
  hold; When the engine is healthy, Then engine-permitted probes flow and
  engine-blocked probes stay blocked (the seal is shadowed) and disabling
  restores the recorded snapshot exactly; When enable fails pre-commit or mid-commit, Then the recorded
  snapshot is restored exactly; When audit is GPO-blocked, Then an
  explicit logged confirm-without-prompts path is offered.
- **AC-7 (FR-08):** Given a tampered, unsigned, or older-version
  correctly-signed pack, When imported, Then it is refused with the
  reason logged (water-mark store prevents rollback); Given a valid
  pack, When enabled/disabled/updated, Then exactly the expected filter
  delta applies and the sidecar state is hash-checked.
- **AC-8 (FR-09):** Given the packs repository CI, When any pack
  changes, Then it is built, signed, and schema-validated on every push.
- **AC-9 (SEC-03):** Given install/disable/uninstall, When it runs,
  Then audit-policy changes are inventoried and exactly reverted
  (default release path), with a startup crash-residue check; inventory
  loss downgrades to warn-and-leave.
- **AC-11 (SEC-02):** Given a re-signed or self-signed binary swap at a
  known path, When it connects, Then the publisher rule stops matching and
  the event is logged (DEC-05 FileMonitor/rule-apply re-validation).
- **AC-10 (NFR-03/SEC-05):** Given the release build, When produced,
  Then the binary set is unchanged (no new exe/dll), size ≤ 8 MB, and
  the sandbox observes no child processes during feature exercise.

## Constraints and quality attributes

Design.md § Traceability Key rows NFR-01..NFR-06, SEC-01/02/03/05,
DATA-01/02 are binding for this round (NFR-04, SEC-04, DATA-03/04 are
Phase 2/3 contracts). Build stays /W4 + /analyze with system libraries
via the established dynamic-resolve pattern (NFR-02); footprint ≤ 8 MB,
no service, no driver (NFR-03); every new string localized (NFR-05);
automated tests without elevation gate the merge (NFR-06, OPS-01
convention: CI when available, else local pre-merge recorded in
verification.md, OPS-04).

## Approved decisions

All of DEC-01..DEC-09 (design.md § Decisions) are binding; planning must
preserve them — any conflict stops implementation and returns to the
design owner. Load-bearing for this round: DEC-01 (fork C chassis), 
DEC-02 (user-space/no driver/no service), DEC-03 (5157-only pipeline +
fallback + degradation state), DEC-04 (guarded Lockdown recipe with
recorded-snapshot rollback), DEC-05 (publisher = signer anchor +
materialized path filters + lazy validation), DEC-07 (licensing hygiene),
DEC-08 (phase gating), DEC-09 (upstream policy).

## Risks and open questions

Carried with owners from design.md § Risks (full mitigation text there):

- RSK-01 — GPO-blockable/reversible audit subcategory; owner=fork-owner; resolution=design.md DEC-03 (fallback + prompt-degradation state) and DEC-04 (confirm-without-prompts Lockdown path); revert-on-uninstall per SEC-03.
- RSK-02 — upstream drift during the multi-phase build; owner=fork-owner; gate=monthly rebase window per DEC-09/OPS-03.
- RSK-03 — AV/SmartScreen false positives; owner=fork-owner; gate=Authenticode decision required before first Phase 1 public release (GPG-only interim documented); wufix System32 path remains flagged per design.
- RSK-05 — multi-month scope; owner=fork-owner; resolution=per-phase independent shipping (DEC-08); Phase 1 alone is a releasable delta.
- RSK-07 — Lockdown negatable by elevated processes; pack key compromise; owner=fork-owner; resolution=threat-model boundary (hardening-consistent) + key rotation documented in packs repo before first release.
- RSK-08 — 5157 Security-log volume under Lockdown; owner=fork-owner; resolution=subscription-side dedup/throttle (FR-01) + documented log-sizing guidance.
- RSK-04 — Phase 3 risk (port-53 conflicts); owner=fork-owner until the Phase 3 round; acknowledged, not actionable this round (DEC-08).
- RSK-06 — Phase 2 risk (managed environments vs ledger quarantine); owner=fork-owner; acknowledged, not actionable this round (DEC-08).

Open question (naming) does not block any phase.

## Traceability Key

Copied verbatim from the approved design (single source of definitions;
downstream artifacts reference but never define keys).
| Key | Meaning |
| --- | --- |
| FR-01 | unified prompt pipeline: primary source = Security-audit event 5157 via EvtSubscribe (5156/success auditing rejected as machine-wide flood); existing FwpmNetEventSubscribe retained as automatic fallback; prompt-degradation state surfaced on tray/status when the audit path is unavailable or reverts mid-session (hardening FR-01 pattern); one deduped prompt per app/connection-class with port merging |
| FR-02 | pre-prompt auto-tiers: existing matching rule → wildcard/pack rule → trusted-publisher rule resolve without prompting; only genuinely novel connections prompt |
| FR-03 | prompt offers publisher binding per DEC-05: signer-hash anchor + materialized path filters; rules survive binary updates; self-signed binaries fall back to path binding |
| FR-04 | decision durations: once / until-restart / always; non-always decisions live as session-scoped state, never written to profile.xml |
| FR-05 | single-flight prompting: at most one prompt visible; concurrent novel connections take the hard default (block — an "ask" default resolves to block inside the single-flight window) and are logged for batch review |
| FR-06 | Lockdown per DEC-04: WFAS default-outbound BLOCK per profile as defense-in-depth backstop for the degraded/stopped-engine case; enable records per-profile defaults + the outbound-allow set and disables that set (survival/app-own excluded); pre-flight audit verification with an explicit logged confirm-without-prompts path when audit is GPO-blocked; **service-scoped** survival rules (svchost + Dhcp/CryptSvc, WSL/ICS — port-wide allows rejected); automatic rollback to the recorded snapshot on any post-commit failure, visible tray state, exact-state restore on disable, keep-or-release on uninstall (default release) |
| FR-07 | blocklist engine: sorted range arrays + binary search replacing per-IP filter explosion; ≥2M entries per zone, ≥32 zones, IPv4+IPv6; same final verdicts as today's engine on the internal pack |
| FR-08 | signed rule packs: versioned JSON pack + detached signature verified against an embedded public key before parsing; tampered/unsigned packs refused and logged; packs enable/disable/update as a unit; pack-state sidecars hash-checked at load from Phase 1 |
| FR-09 | packs repository (separate repo): pack schema docs + first three packs (Telemetry-Refresh, Vendor-blockers, AI-Agents) + CI that builds/signs/validates every pack |
| FR-10 | audit ledger: WFAS rule store diffed against a persisted baseline (DATA-03); foreign add/modify/delete surfaced in an Audit tab; optional quarantine disables the foreign rule pending review — approve restores exactly; reject keeps it disabled permanently and flagged (deletion is a separate explicit action; a recreated rule is re-flagged as new); policy-managed rules (origin = policy store: GPO rules live under `HKLM\SOFTWARE\Policies\Microsoft\WindowsFireWall\FirewallRules` vs the local FirewallProfiles store; MDM/CSP origin finalized as a heuristic in the phase spec) are reported, never quarantined |
| FR-11 | incremental filter apply: diff-based add/remove of changed filters only, preserving the hardening tri-state transaction contract and the applying-never-sticks invariant |
| FR-12 | profile + derived-state integrity (Phase 2): config directory ACL hardening; ledger baseline tamper-evident (hash-checked at load; corrupt ⇒ refuse + rebuild from source of truth); pack version high-water marks live in `pack_watermarks.json`, outside the rebuildable set (lost/corrupt ⇒ affected packs refuse until re-confirmed — DATA-02) |
| FR-13 | domain layer interface contract (Phase 3): resolver-ownership + ETW DNS attribution + TTL-clamped IP↔domain cache; no driver, no service; implemented under its own future design round consuming this key unchanged |
| FR-14 | secure DNS contract (Phase 3): DoH/DoT upstream via the same resolver; DNS-leak prevention = detect and block apps bypassing the resolver; rides FR-13 |
| SEC-01 | a pack that fails signature or schema validation never contributes a single filter; refusal is logged with reason |
| SEC-02 | publisher rules bind only to chains that validate under WinVerifyTrust at every materialization/apply point (DEC-05); a binary whose signer no longer validates drops out of the publisher set (logged), never silently permitted |
| SEC-03 | audit-policy machine changes are inventoried at install (recorded prior subcategory + SCENoApplyLegacyAuditPolicy state, stored per DATA-01) and exactly reverted at uninstall/disable (default release path), with a startup consistency check covering crash residue; loss of the inventory downgrades revert to warn-and-leave (logged) — exact revert is guaranteed only while the inventory exists |
| SEC-04 | Phase 3 domain data (domains, DNS cache) is stored locally only; no telemetry egress; opt-out removes stored data |
| SEC-05 | no new elevated execution path: every new feature runs inside the existing elevation model; no helper binaries, no downloaded executables, no new processes |
| NFR-01 | zero UX regression on paths that never fail (hardening NFR-01 inheritance); journey 7 is the acceptance surface |
| NFR-02 | MSVC build green at /W4 + /analyze with system libraries only, consumed via the established dynamic-resolve pattern as needed (no new package dependencies) |
| NFR-03 | footprint: installed size ≤ 8 MB, single portable binary, no service, no driver; CI-checked in the SEC-05 inventory job |
| NFR-04 | rule-apply: incremental p95 ≤ 1.1 × full-rebuild p95 in a back-to-back same-session run (authoritative procedure); unfiltered window (apply-transaction wall time where effective policy ≠ target) strictly smaller than the full-rebuild path |
| NFR-05 | every new UI string ships localized through the existing i18n pipeline |
| NFR-06 | every new module carries automated tests runnable without elevation; the gate (CI when available, local pre-merge otherwise — same convention as OPS-01) must be green to merge (composite rounds) |
| DATA-01 | profile.xml remains v5 wire-compatible; new state lives in namespaced sidecar files (pack state, ledger baseline, audit-policy inventory), never in profile.xml |
| DATA-02 | pack format: `packs/<id>/pack.json` + detached signature, semver, key-id field + monotonic version (anti-rollback — the per-pack version high-water mark persists in a dedicated non-rebuildable sidecar, `pack_watermarks.json`, outside FR-12's rebuild scope), explicit rule schema (apps/publisher/ports/addresses/direction) |
| DATA-03 | ledger baseline: JSON snapshot of WFAS rule identities (name+hash), rebuildable on demand |
| DATA-04 | Phase 3 cache contract: TTL clamp (floor 17 s), bounded retention past expiry, CNAME-chain retention — exact numbers set by the Phase 3 round |
| OPS-01 | every composite implementation round runs `goldfish check` against this design — in CI where available; until the fork gains CI it is a required local pre-merge step recorded in verification.md (OPS-04); a failing gate blocks merge (composite chains only — DEC-08) |
| OPS-02 | releases are Authenticode + GPG signed binaries with winget manifest automation (certificate acquisition = open question) |
| OPS-03 | monthly upstream rebase window; upstream-overlapping features pulled not duplicated (operational arm of DEC-09) |
| OPS-04 | each shipped round carries CHANGELOG entries + a verification.md following the hardening convention |
| DEC-01 | chassis is the existing fork C codebase; no rewrite; amwall is reference only |
| DEC-02 | identity: user-space, no driver, no service; bandwidth shaping rejected, observation pulled from upstream |
| DEC-03 | prompt pipeline unified on Security-audit event 5157 with net-event fallback; audit subcategory enabled at install, reverted at uninstall/disable, crash-checked at startup; prompt-degradation state surfaced |
| DEC-04 | Lockdown = WFAS-layer defense-in-depth backstop with the stated arbitration contract (app sublayer outranks mpsvc while healthy); guarded recipe: verify-then-commit, survival rules, rollback, tray state |
| DEC-05 | publisher rules = signer-hash anchor + materialized path filters re-validated under WinVerifyTrust at every materialization/apply point; AppID-driver route excluded by DEC-02 |
| DEC-06 | Phase 3 domain layer shape fixed (resolver ownership + ETW attribution + TTL cache + bloom); internals deferred to its own round |
| DEC-07 | licensing hygiene: code only from GPL-3-compatible sources with per-file audit (Portmaster core GPL-3.0 yes; safing/spn AGPL-3.0, minimalfirewall AGPL-3.0, unlicensed repos, GPL-2-only = ideas only); upstream attribution headers required |
| DEC-08 | process: umbrella design approved once; per-phase goldfish-gated chains consume keys, never invent them; amendments require revision bump + design-owner approval; hardening rounds keep merge precedence and run against their own key space |
| DEC-09 | monthly upstream rebase; pull overlapping upstream features; fork code namespaced for rebase cost |
| RSK-01 | audit subcategory is machine-wide and GPO-blockable/reversible; prompt-degradation state + fallback + revert-on-uninstall carried as the answer; Lockdown under a blocked subcategory proceeds only via explicit logged confirm-without-prompts (DEC-04) |
| RSK-02 | upstream drift during multi-phase build; monthly rebase + namespacing carried as the answer |
| RSK-03 | AV/SmartScreen false-positive risk on new behaviors; wufix System32 path remains (hardening RSK-03) and stays flagged; Authenticode+GPG signing from Phase 1 |
| RSK-04 | port-53 conflict surfaces in Phase 3; detect-and-report contract, no silent override; owner: fork owner until Phase 3 round |
| RSK-05 | multi-month scope; per-phase independent shipping is the mitigation |
| RSK-06 | managed environments: ledger quarantine would fight GPO/Intune; policy-managed rules reported, never quarantined |
| RSK-07 | Lockdown negatable by other elevated processes (threat-model boundary, hardening-consistent); pack key compromise mitigated by key-id + monotonic version + documented rotation |
| RSK-08 | Security-log volume under Lockdown (every outbound attempt = 5157); subscription-side dedup/throttle + documented log-sizing guidance; failure mode degrades to Windows' own audit behavior, never a silent app failure |
