# Specification: Composite Phase 1 (Trust-aware prompting, Lockdown, Packs)

Derived from `handoff.md` (design revision `2026-11-06-r5`, approved).
Phase boundary per DEC-08: Phase 1 implements FR-01..FR-06, FR-08, FR-09
with their dependent attributes; FR-07/FR-10/FR-11/FR-12/FR-13/FR-14 are
deferred contracts recorded below, never implemented this round.

## User stories

- **US1:** As a user, when an unknown app first connects I get exactly
  one prompt (never a storm), and my allow decision can bind to the
  app's publisher so it survives updates (FR-01, FR-03, FR-05).
- **US2:** As a user, my once/until-restart decisions clean up after
  themselves and never pollute my saved profile (FR-04, DATA-01).
- **US3:** As a cautious user, one switch seals my machine even if the
  firewall itself degrades or is stopped — and never locks me out blind
  (FR-06, DEC-04).
- **US4:** As a user, I can import community rule packs that are
  cryptographically verified, versioned, and reversible as a unit
  (FR-08, FR-09, SEC-01, DATA-02).
- **US5:** As a privacy-conscious user, the machine-wide audit change
  the app makes is inventoried and exactly reverted when I uninstall or
  disable (SEC-03, DEC-03).
- **US6:** As a user, none of the new features spawn processes, download
  executables, or gain elevation (SEC-05, NFR-03).

## Functional requirements (Phase 1)

- **FR-01 prompt pipeline:** Given the audit subcategory
  `{0CCE9226-…}` enabled at install/enable time, When any WFP block
  (EventID 5157) occurs, Then the pipeline produces one deduped prompt
  per app/connection-class with merged ports; When the audit path is
  unavailable or reverts mid-session, Then the existing
  FwpmNetEventSubscribe fallback engages automatically and a
  prompt-degradation state appears on tray/status (hardening FR-01
  pattern). Success auditing (5156) is never enabled (DEC-03).
- **FR-02 auto-tiers:** Given a connection matching an existing rule, a
  wildcard/pack rule, or an already-materialized trusted publisher,
  When it occurs, Then no prompt appears; only genuinely novel
  connections prompt.
- **FR-03 publisher binding:** Given a signed binary prompts, When the
  user selects "Always for this publisher", Then a signer-hash-anchored
  rule is stored and its path set materializes at three re-validating
  points — (a) prompt time, (b) the FileMonitor re-hash loop (10-minute
  cadence, src/helper.c:1603), (c) rule-apply; a binary at a new path
  is lazily signer-checked at connection (cached per path+mtime),
  permitted and logged on match, prompted on mismatch; self-signed
  binaries are offered path binding only (DEC-05).
- **FR-04 durations:** Given a prompt decision, When once/until-restart/
  always is chosen, Then non-always decisions live in session state
  only and never appear in profile.xml.
- **FR-05 single-flight:** Given concurrent novel connections, When
  more than one arrives, Then exactly one prompt is visible and the
  others take the hard default (block — an "ask" default resolves to
  block inside the window) and are logged for batch review.
- **FR-06 Lockdown:** Given the guarded recipe, When enabled, Then the
  app records per-profile WFAS defaults + the outbound-allow set,
  verifies the audit subcategory (or offers the logged
  confirm-without-prompts path under GPO), pre-creates service-scoped
  survival rules (svchost + Dhcp/CryptSvc; WSL/ICS; port-wide allows
  rejected), sets default-outbound BLOCK, and disables the recorded
  allow set (survival and app-own rules excluded — DEC-04 step 5); any pre-commit failure aborts, any post-commit failure
  rolls back to the recorded snapshot; disable restores the snapshot
  exactly; uninstall asks keep-or-release (default release); tray state
  is visible throughout (DEC-04).
- **FR-08 signed packs:** Given a pack (pack.json + detached signature,
  key-id, monotonic version), When imported/enabled/disabled/updated,
  Then the signature verifies against the embedded public key before
  any rule parses, the unit applies exactly its filter delta, sidecar
  state is hash-checked at load, and the version high-water mark in
  `pack_watermarks.json` refuses older correctly-signed packs
  (anti-rollback); the water-mark store sits outside any rebuild set
  (SEC-01, DATA-02).
- **FR-09 packs repository:** Given the separate packs repo, When
  maintained, Then it carries the schema docs and the first three packs
  (Telemetry-Refresh, Vendor-blockers, AI-Agents) with CI that builds,
  signs, and schema-validates every pack on push.

## Deferred contracts (recorded per DEC-08 — NOT this round)

- **FR-07** zones/bsearch blocklist engine, **FR-10** audit ledger,
  **FR-11** incremental apply, **FR-12** config ACL + baseline
  integrity, **NFR-04** incremental-apply budgets: Phase 2.
- **FR-13** domain layer, **FR-14** secure DNS, **SEC-04** local-only
  DNS data, **DATA-04** cache contract, **RSK-04** port-53 conflicts:
  Phase 3. **DATA-03** ledger baseline and **RSK-06** managed-env
  quarantine: Phase 2 with FR-10.

## Quality attributes and constraints

- **NFR-01** zero UX regression on never-failing paths (journey 7);
  **NFR-02** /W4 + /analyze green, system libraries via the established
  dynamic-resolve pattern, no new package deps; **NFR-03** ≤ 8 MB,
  single portable binary, no service/driver, CI-checked in the SEC-05
  inventory job; **NFR-05** every new string localized; **NFR-06**
  automated tests without elevation gate the merge (OPS-01 convention).
- **SEC-01** unsigned/tampered pack never contributes a filter;
  **SEC-02** publisher rules bind only to WinVerifyTrust-valid chains at
  every materialization and rule-apply point (including FileMonitor
  re-validation); **SEC-03** audit changes inventoried at
  install (DATA-01), exactly reverted at uninstall/disable with startup
  crash-residue check, loss downgrades to warn-and-leave; **SEC-05** no
  new elevated paths, helper binaries, downloaded executables, or
  processes.
- **DATA-01** profile.xml stays v5 wire-compatible; pack state, ledger
  baseline, and audit-policy inventory live in namespaced sidecars;
  **DATA-02** pack format: `packs/<id>/pack.json` + detached signature,
  semver, key-id, monotonic version, explicit rule schema.
- **OPS-01** `goldfish check` gates the merge (CI when available, else
  local pre-merge recorded per **OPS-04**); **OPS-02** Authenticode +
  GPG releases with winget automation (cert decision before first
  public release); **OPS-03** monthly upstream rebase.

## Acceptance criteria

The handoff's AC-1..AC-11 are binding verbatim (handoff.md § Acceptance
criteria), executed per the design's verification split: automated items
in the sandbox bench, manual procedures documented in this round's
verification.md.
