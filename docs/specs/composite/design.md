# Design: Composite — Fork Product Evolution (Umbrella Architecture)

> Revision `2026-11-06-r5` — the fourth full goldfish pass
> (`review-r4.md`: 6 blocking — three of them regressions of r4's own
> partial fixes — + 8 suggestions) is fully addressed: unified
> non-rebuildable water-mark store, service-scoped survival rules with an
> executable degraded-direction test, post-commit rollback route,
> per-zone load configuration, unfiltered-window metric, orphan keys
> wired, audit-optional Lockdown, 5157-storm risk, reject semantics,
> pinned burst precondition, lane-ownership fixes, SEC-03 inventory home.
> Elephant
> evidence base: `D:\CV\Github\_sw-dd\DEEP-DIVE-REPORT.md` (9-repo code
> teardown, 2026-11-06) plus the approved hardening-round-1 chain (r4,
> gates exit 0). Human approval gate: **PASSED — recorded 2026-11-06**.
> The design owner approved the composite direction and authorized
> implementation in session, verbatim: «هذه هي فقط للتجربة لاكني لا
> مشكلة لدي في حالت انه قدرنا نوصل لمحتوي العام والكبير الخاص بكيفية
> الوصول الي افضل شكل ونسخة ممكنة مع جمع الممميزات من مختلف النسة في
> مكان واحد نبداء في تطبيقة والعمل علي الوصلو الي اصلاحات المناسبة في
> الوقت الحالي» — umbrella (r5) approved as the product shape; the
> Phase 1 chain (handoff → spec → plan → tasks) is authorized to start;
> Phase 2/3 remain governed by DEC-08 per-phase chains.
>
> Key-namespace convention: keys in this table are composite keys,
> consumed only by composite-phase chains. Hardening chains keep their own
> key space; cross-references to inherited contracts are always written as
> "hardening FR-xx/DEC-xx" (DEC-08).

## Problem and intended outcomes

The fork today is a hardened simplewall: same whitelist WFP engine, same
prompt UX, same per-IP blocklist explosion (1,496 individual
`FwpmFilterAdd0` calls, `bin/profile_internal.xml`). The 2026-11-06 teardown
of 9 peer firewalls found every missing capability already exists as proven,
portable design — but scattered across codebases with incompatible
identities (kernel drivers, .NET runtimes, AGPL, closed source). No single
tool combines: no-driver lightness + domain-level filtering + smart
prompting (publisher rules, durations, single-flight) + guarded lockdown +
community rule packs. That combination is the fork's product lane
(DEC-01).

Intended observable outcomes (per phase; each phase ships independently —
RSK-05):

1. **Phase 1 — Trust-aware prompting and lockdown.** A first unknown
   outbound connection produces one prompt (never a storm), offering
   allow/block decisions that can bind to the binary's Authenticode
   publisher rather than its path, with once/until-restart/always
   durations; a one-switch Lockdown mode seals the machine at the Windows
   Firewall layer as a defense-in-depth backstop that holds while the
   app's engine is degraded or the app is stopped, with pre-flight
   verification and recorded-state rollback; uninstall asks keep-or-release
   (default: release + restore) (FR-01, FR-02, FR-03, FR-04, FR-05,
   FR-06, DEC-03, DEC-04, DEC-05).
2. **Phase 1 — Packs.** Signed, versioned rule packs install from a
   separate packs repository: Telemetry-Refresh, Vendor-blockers,
   AI-Agents (presets constraining known AI coding CLIs/MCP endpoints);
   an unsigned or tampered pack never applies, and pack state sidecars
   are hash-checked from day one (FR-08, FR-09, SEC-01, DATA-02).
3. **Phase 2 — Accountability and scale.** Third-party changes to the
   Windows firewall rule store are detected, baselined, and (optionally)
   quarantined pending review; the blocklist engine swaps per-IP filter
   explosion for sorted range arrays with binary search; config-directory
   ACL hardening lands (FR-07, FR-10, FR-11, FR-12).
4. **Phase 3 — Domain layer (interfaces only in this design).** A
   user-space (no driver) domain-filtering layer: resolver ownership +
   ETW DNS-Client attribution + TTL-disciplined IP↔domain cache; DoH/DoT
   and DNS-leak prevention ride the same resolver. Implementation gets its
   own design round consuming FR-13/FR-14/SEC-04/DATA-04 unchanged;
   this document fixes the interfaces and non-negotiable constraints only
   (DEC-06).

Out of scope everywhere, permanently: kernel driver, Rust rewrite,
alternative UI toolkit, telemetry egress, DPI-circumvention bundling.

## In scope and out of scope

- **In scope:** `src/` C code (fork only, per DEC-01); system libraries already
  linked by the project plus `wevtapi`, consumed via the existing
  dynamic-resolve pattern (`src/log.c:294-391`) — dnsapi/iphlpapi users
  arrive only with Phase 3, whose internals stay out of scope until their
  own round; a new sibling packs repository; CI workflows; docs/i18n.
- **Out of scope:** the `routine` submodule (still external — same
  posture as hardening DEC-01); profile-format v6 redesign (v5 stays wire
  compatible, DATA-01); DPAPI migration (carried as hardening RSK-01);
  implementing Phase 3 internals; monetization surfaces.

## User journeys and behavior

1. First run after install: an unknown app connects. Today: one popup
   (existing net-event pipeline). Now: identical popup, but the decision
   row offers "Always allow for publisher <signer>" when the binary
   validates; the publisher rule anchors on the signer hash and
   materializes path filters for that signer's binaries, so the decision
   survives the app's next update (FR-03, SEC-02, DEC-05).
2. A chatty installer spawns 40 processes at once. Today: popup queue
   processes serially with a 60 s per-app rate limit
   (`src/notifications.c` + `main.h:154`). Now: one prompt is on screen
   (single-flight); every other novel connection is held to the hard
   default (block — see FR-05) and lands in the log for batch review;
   "allow until restart" decisions clear the noise without polluting the
   profile (FR-04, FR-05).
3. User flips Lockdown before opening a suspicious document. The app
   records the current per-profile WFAS defaults and the existing
   outbound-allow rule set, verifies the WFP audit subcategory is
   actually enabled (`AuditQuerySystemPolicy`, subcategory
   `{0CCE9226-…}`), pre-creates WFAS survival rules (DHCP, CryptSvc,
   WSL), then sets WFAS default-outbound BLOCK per profile and disables
   the recorded outbound-allow set (survival and app-own rules
   excluded); any verification failure aborts before anything is
   committed — it never locks the user out blind; if the audit
   subcategory cannot be enabled (GPO), an explicit confirm-without-
   prompts path (logged) is offered instead of a hard refusal; any later
   failure rolls back to the recorded snapshot (FR-06, DEC-04).
4. User imports the AI-Agents pack. The pack file's detached signature is
   verified against the embedded public key before a single rule parses;
   its sidecar state is hash-checked at load; a tampered pack or state is
   refused and logged; an applied pack shows its source and version in
   the UI and can be enabled/disabled/updated as a unit
   (FR-08, FR-09, SEC-01, DATA-02).
5. Another program (or the user's teenager) adds a firewall allow-rule
   while Lockdown or normal mode is on. The ledger loop diffs the WFAS
   rule store against the baseline snapshot (DATA-03), flags the foreign
   change in the Audit tab, and — when quarantine mode is on — disables
   it pending review, restoring it exactly on approve; rules identified
   as policy-managed (GPO/Intune) are never quarantined, only reported
   (FR-10, DATA-03, RSK-06).
6. Uninstall, disable of notifications, or a crash-consistency check at
   next startup removes the audit-policy configuration the app
   introduced (Filtering-Platform-Connection audit subcategory
   enablement + `SCENoApplyLegacyAuditPolicy`), leaving the machine as
   found — with one explicit exception: uninstalling while Lockdown is
   ON presents keep-or-release, and the default (release) performs the
   full revert (SEC-03, DEC-03, DEC-04).
7. Every feature above runs inside the existing elevation model: no
   helper binaries, no downloaded executables, no new processes
   (SEC-05, NFR-01).

## Decisions

- **DEC-01: chassis.** Evolution of the existing fork C codebase — no
  rewrite. `amwall` (Rust, 40k LOC, 350 tests) is a monitored competitor
  and design reference, never a merge target; two languages would split
  the effort. Evidence: teardown §6.
- **DEC-02: identity = user-space, no driver, no service.** Every feature
  must work in-process from the existing single binary. Bandwidth *shaping*
  (Fort's token bucket) requires kernel callouts — rejected; bandwidth
  *observation* comes from upstream v3.9.1's ETW UDP stats + TCP EStats
  (WFN pattern) pulled via upstream sync, not rebuilt (an upstream-sync
  deliverable outside the composite key space — DEC-09/OPS-03).
- **DEC-03: prompt pipeline = Security-audit events, unified, 5157 only.**
  Primary prompt source: `EvtSubscribe` on channel "Security" filtering
  **EventID 5157** (WFP blocked connection) — success auditing (5156) is
  explicitly rejected: it would log every permitted connection
  machine-wide (log-wrap flood) and prompts never need it. Gated by
  enabling the audit subcategory `{0CCE9226}` (+ 
  `SCENoApplyLegacyAuditPolicy=1`) at install/enable, inventoried and
  exactly reverted at uninstall/disable, with a startup consistency check
  for crash residue (SEC-03). This captures all WFP block verdicts
  system-wide (including our own filters) instead of only self-subscribed
  net events; the existing `FwpmNetEventSubscribe` pipeline remains as
  automatic fallback. Because the audit subcategory is machine-wide and
  GPO-blockable (RSK-01), the pipeline owns a **prompt-degradation state**:
  subscription health is checked continuously, runtime audit reversion is
  detected, the fallback engages automatically, and the degraded state is
  surfaced on tray/status exactly per the hardening FR-01 pattern — never
  silently. Popup-suppression matcher ("already covered by a rule → no
  prompt") and port-merge dedup port from the WFN design; culture-invariant
  direction parsing via raw `LayerRTID` ints, never localized `%%14592/93`
  strings.
- **DEC-04: Lockdown = WFAS-layer defense-in-depth backstop.** Arbitration
  contract, stated explicitly: the app's own WFP sublayer weight (0xFFFF,
  `src/wfp.c:275`) outranks mpsvc's, so while the engine is healthy its
  verdicts govern and the WFAS seal is shadowed; when the engine degrades,
  is disabled, or the app is stopped (hardening FR-01 degraded state), the
  WFAS seal governs instead — Lockdown is what keeps a degraded machine
  sealed instead of merely visible. Because specific WFAS outbound-allow
  rules outrank the default action, the enable sequence makes the seal
  real: (1) record per-profile defaults + the existing outbound-allow
  rule set, (2) verify the audit subcategory via `AuditQuerySystemPolicy`
  *before* committing — if it cannot be enabled (GPO, RSK-01), Lockdown
  proceeds only after explicit user confirmation to run without
  connection prompts (logged); the seal itself does not depend on audit,
  (3) pre-create survival rules — **service-scoped** WFAS rules
  (program = svchost.exe, ServiceName = Dhcp / CryptSvc) plus the
  WSL/Hyper-V ICS service rule; port-wide allows are explicitly rejected
  because they would dissolve the seal; they exist for exactly the
  degraded/absent case where simplewall's own permits are gone, (4) set
  `INetFwPolicy2::DefaultOutboundAction = BLOCK` per profile, (5) disable
  the recorded outbound-allow set (survival and app-own rules excluded).
  Any failure rolls back to the **recorded snapshot** — never an
  unconditional ALLOW, so a host already sealed tighter is never
  loosened; disable restores the snapshot exactly. Uninstall while
  Lockdown is ON asks keep-or-release; the default (release) performs
  the full revert. Residual
  risk: another
  elevated process can flip these flags back — accepted by threat model,
  same boundary the hardening chain draws (RSK-07). Idea-source is AGPL —
  design translated, zero code copied (DEC-07).
- **DEC-05: publisher rules = signer-hash anchor + materialized path
  filters.** WFP ALE conditions match app-path blobs, not signers (the
  AppID driver route is excluded by DEC-02), so a publisher rule is stored
  as: signer hash chain + semver + the materialized path set. Materializa-
  tion points: (a) prompt time (capture signer + path), (b) the existing
  FileMonitor re-hash loop (`src/helper.c:1603`, 10-minute cadence) detects
  new/changed binaries under monitored paths, (c) rule-apply. Every
  materialization re-validates the binary under `WinVerifyTrust` before
  adding its path filter; a binary whose signer no longer validates drops
  out of the set (logged) — that is SEC-02's defined trigger. Self-signed
  binaries never qualify for publisher binding (path rules only). This
  closes the update-breaks-rule and path-spoofing classes without a
  driver. Lazy validation closes the loop for updates: a binary at a
  previously unseen path is signer-checked at connection time
  (`WinVerifyTrust`, cached per path+mtime) against publisher anchors —
  a match materializes the path and permits without prompting (logged);
  a mismatch falls through to the normal prompt. An update at a new
  path therefore never re-prompts and never silently passes.
- **DEC-06: domain layer shape (Phase 3 contract).** User-space only:
  (a) system resolver points at an in-process local resolver (self-check
  verified), (b) per-app DNS attribution via the
  `Microsoft-Windows-DNS-Client` ETW provider, (c) IP↔domain cache with
  clamped TTLs and bounded retention, (d) bloom prefilter + exact
  secondary lookup for blocklists. Hard constraints: no driver, no
  service, local-only storage (SEC-04), port-53 conflict detected and
  reported, not silently overridden (RSK-04, owner: fork owner until the
  Phase 3 round designates otherwise).
- **DEC-07: licensing hygiene.** Design ideas may come from anywhere;
  code may come only from GPL-3-compatible sources with per-file license
  audit at port time: simplewall itself, Fort (GPL-3), WFN (GPL-3),
  Portmaster core (safing/portmaster = GPL-3.0, GitHub-API verified
  2026-11-06). Excluded: safing/spn (AGPL-3.0, archived), minimalfirewall
  (AGPL-3.0), unlicensed repos (BlockEDRTraffic, zapret),
  GPL-2.0-only code (winappguard). Every ported file retains upstream
  attribution headers.
- **DEC-08: process.** This umbrella design is approved once; each phase
  runs its own `handoff → spec → plan → tasks` chain checked by
  `goldfish check` against this design's keys (composite chains only —
  hardening chains run against their own design, so OPS-01 cannot
  false-fail them). A phase chain may only consume keys, never invent
  them; a genuinely novel requirement amends THIS design: revision bump +
  explicit design-owner approval recorded in the header, then the new key
  is consumable. Hardening rounds continue unchanged and take precedence
  for merge order.
- **DEC-09: upstream policy.** Monthly rebase window against
  `henrypp/simplewall` (alive: v3.9.2 mid-cycle, pushed 2026-11-05);
  upstream features that overlap composite work (e.g. `udpstats.c`) are
  pulled, not duplicated. Fork features are confined to fork-namespaced
  files where practical to keep rebase cost low (the operating answer to
  RSK-02).

## Verification split (honest automatable/manual)

Every shipped round carries CHANGELOG entries plus a verification.md
following the hardening convention (OPS-04); the split below seeds each
phase spec's acceptance criteria.

- **Automated (sandbox bench, per the hardening T016 companion pattern):**
  - FR-01 primary pipeline: in the test VM enable the audit subcategory,
    create a WFAS block rule for a probe binary, run the probe → 5157
    arrives → prompt/dedup path asserted; then disable the subcategory
    mid-session → fallback engages and the prompt-degradation state is
    surfaced (DEC-03).
  - FR-02 tiers: connection matching an existing rule / wildcard or
    pack rule / already-materialized trusted publisher → no prompt,
    logged only (FR-02).
  - FR-04 durations: once/until-restart decisions verified present in
    session state and verified absent from profile.xml on disk.
  - FR-05 single-flight: 40-connection burst from 40 distinct probe
    processes → exactly one prompt window;
    the other 39 hold at block and appear in the log.
  - FR-06 pre-commit abort: force audit-verification failure at enable
    step (2) → nothing was committed; WFAS state is unchanged by
    definition and the app surfaces the abort (DEC-04).
  - FR-06 post-commit rollback: induce a mid-sequence failure after the
    commit began (sandbox forces the step-(5) allow-set disable to fail
    partway) → the app rolls back to the recorded snapshot: defaults
    restored, the partially-disabled allow set re-enabled, survival
    rules removed, failure surfaced (DEC-04).
  - FR-06 arbitration, degraded direction (DEC-04): degrade the engine
    (delete the app's provider filters per the hardening FR-01 path)
    with Lockdown on → an un-permitted probe binary is denied by the
    WFAS seal; the sandbox asserts the survival rules exist with their
    defined service-scoped shape (program = svchost.exe + ServiceName =
    Dhcp / CryptSvc, plus the WSL/ICS service rule) and that
    non-matching probes stay denied; functional DHCP/CryptSvc continuity
    while locked is the manual-lane check.
  - FR-06 arbitration, stopped direction (DEC-04): terminate the app
    process with Lockdown on → the seal still denies (no lane depends
    on the app running); relaunching resumes normal arbitration.
  - FR-06 arbitration, healthy direction (DEC-04): engine healthy with
    Lockdown on → an engine-permitted probe flows and an engine-blocked
    probe stays blocked (the seal is shadowed — no behavior change);
    disable restores the recorded snapshot exactly (defaults, the
    disabled allow set re-enabled, survival rules removed).
  - FR-07 zones: 32 zones × 2M entries each (64M entries total) load
    ≤ 30 s wall, per-lookup p99 ≤ 10 µs, resident set ≤ 128 MB with all
    zones loaded (budgets owned by this lane; NFR-04 covers
    rule-apply only); equivalence test —
    same final verdicts as the current engine on the internal pack
    (FR-07).
  - FR-08 packs: tamper test (flip one byte → refusal + log); unit
    enable/disable/update produces exactly the expected filter delta
    (FR-08, SEC-01); anti-rollback test — precondition: a higher-version
    pack was previously applied (persisting its version high-water mark
    in the dedicated non-rebuildable water-mark store, DATA-02), then
    serve an older-version
    correctly-signed pack → refused with the anti-rollback reason
    logged; sidecar hash-check refuses a corrupted state file.
  - FR-09 packs repo: CI in the packs repo builds, signs, and
    schema-validates all three packs on every push (FR-09).
  - FR-10 ledger: add/modify/delete a rule out-of-band → detected with
    correct kind; quarantine disables and an approve restores the exact
    prior state (FR-10); the sandbox constructs a policy-store rule
    (under the GPO Policies key, per the FR-10 detection contract) →
    reported, never quarantined (RSK-06).
  - FR-11 incremental apply: equivalence test — same final filter set as
    full rebuild on a synthetic profile; p95(incremental) ≤ 1.1 ×
    p95(full rebuild) in a back-to-back same-session run (the
    authoritative procedure — NFR-04); unfiltered window (apply-
    transaction wall time during which effective policy ≠ target)
    asserted strictly smaller than the full-rebuild path in the same
    run, with zero full-teardown applies in steady state (FR-11,
    NFR-04).
  - FR-12 integrity: corrupted ledger baseline / pack-state sidecar →
    refuse + rebuild from source of truth (rebuild covers the ledger
    baseline and pack preferences only); `pack_watermarks.json` is
    outside the rebuild set — corrupt or absent ⇒ affected packs refuse
    until re-confirmed, so corruption cannot reset anti-rollback
    (FR-12 + DATA-02).
  - SEC-02: re-sign/self-signed binary swap → publisher rule stops
    matching, logged (DEC-05 trigger).
  - SEC-05 build inventory: CI asserts the release produces exactly the
    existing binary set (no new exe/dll), NFR-03 size budget checked in
    the same job; the sandbox bench watches for child processes during
    feature exercise and asserts none (in-process Audit* APIs — no
    auditpol.exe spawn — satisfy the no-new-processes promise).
- **Manual, documented procedure:** uninstall revert of audit policy
  (`auditpol /get /subcategory:{0CCE9226-…}` before/after, SEC-03);
  GPO-locked fallback path on a domain-joined VM (RSK-01); publisher-rule
  survival across a real app update (FR-03, DEC-05); i18n sweep of every
  new string (NFR-05); build gate — MSVC `/W4` + `/analyze` clean on every
  touched file (NFR-02; NFR-06's test gate runs in the automated lane —
  CI when available, local pre-merge otherwise, same convention as
  OPS-01).

## Risks and open questions

- **RSK-01:** enabling the audit subcategory is a machine-wide change;
  GPO can block it at enable time or revert it at runtime
  (`SCENoApplyLegacyAuditPolicy`). Mitigation: prompt-degradation state +
  automatic fallback (DEC-03), documented manual procedure, revert on
  disable/uninstall (SEC-03). Owner: fork owner.
- **RSK-02:** upstream drift — henrypp ships v3.9.x mid-cycle while the
  composite adds thousands of lines. Mitigation: DEC-09 monthly rebase
  executed as the OPS-03 window + fork-namespaced files. Owner: fork owner.
- **RSK-03:** AV/SmartScreen false positives on new behaviors
  (audit-policy mutation via in-process Audit* APIs, pack verification).
  Honest status: the wufix
  System32 path REMAINS in the codebase (hardening RSK-03 deferred the
  redesign; only ImagePath preservation landed) and is the single known
  System32-touching path — it stays flagged. Mitigations: Authenticode
  code-signing + GPG from Phase 1 (OPS-02 — note GPG alone does not build
  SmartScreen reputation), signed packs — the Authenticode half is
  conditional on the open question below, which MUST be decided before
  the first Phase 1 public release; until then releases are GPG-only and
  this mitigation is partially void (accepted, dated). Owner: fork owner.
- **RSK-04:** local resolver port-53 conflicts (VPN clients, existing
  local DNS tools) surface only in Phase 3. Mitigation: detect-and-report
  contract (DEC-06), not silent override. Owner: fork owner until the
  Phase 3 round designates otherwise.
- **RSK-05:** scope ambition (three phases, months of work). Mitigation:
  DEC-08 per-phase chains ship independently; Phase 1 alone is a
  releasable product delta. Owner: fork owner.
- **RSK-06:** managed environments (GPO/Intune deploy firewall rules);
  ledger quarantine fighting the management tool. Mitigation: policy-
  managed rules are reported, never quarantined (FR-10 journey 5).
  Owner: fork owner.
- **RSK-07:** Lockdown is negatable by any other elevated process; also
  pack signing-key compromise would let signed-but-malicious packs apply.
  Mitigations: elevated-attacker boundary accepted per threat model
  (same as hardening); for pack replay, key-id + monotonic version with
  anti-rollback (DATA-02); for novel malicious packs under a compromised
  key, anti-rollback does not help — the mitigation is documented key
  rotation in the packs repo before first release, with the residual
  window accepted. Owner: fork owner.
- **RSK-08:** Security-log volume under Lockdown: with the engine
  degraded, every outbound attempt is a WFAS default-block and therefore
  a 5157 event; a chatty machine can fill the Security log (wrap, or a
  stop under no-overwrite retention). Mitigations: subscription-side
  dedup/throttling (FR-01), documented log-sizing guidance in the
  Lockdown UI; the failure mode degrades to Windows' own audit
  behavior, never a silent app failure. Owner: fork owner.
- **Open question (design owner):** product naming/branding — the fork's
  identity diverges from "simplewall" the moment Phase 1 ships (no phase
  blocked). Authenticode certificate acquisition for OPS-02: must be
  decided BEFORE the first Phase 1 public release (RSK-03 dependency);
  GPG-only interim is the documented fallback.

## Traceability Key

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
