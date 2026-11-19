# Composite Phase 1 verification (T013/T016)

> Manual procedures and gate record. Automated probes: T012 scope (pending).
> Interactive GUI checklist lives separately in
> `docs/specs/composite/verification-checklist.md` (owner run, 2026-11-10).

## Manual procedures (OPS-04, SEC-03, FR-03, NFR-05, FR-06)

### M1 — GPO-locked fallback VM (RSK-01, FR-01)

1. VM with a GPO that disables the `Audit Filtering Platform Connection`
   subcategory and/or blocks `SCENoApplyLegacyAuditPolicy` changes.
2. Install the fork, enable composite prompting.
3. EXPECT: prompt-degradation state surfaces (never silent), the
   FwpmNetEventSubscribe fallback engages automatically, and the 5157
   feed is shown as degraded in tray/status.

### M2 — Uninstall revert, before/after (SEC-03, FR-06)

1. Enable composite audit + Lockdown; change a firewall default manually
   while engaged.
2. Run `-uninstall` with confirmation; choose RELEASE (default).
3. EXPECT: audit subcategory restored to the recorded prior values;
   Lockdown snapshot restored exactly (defaults + rule states); survival
   rules removed; no unconditional ALLOW ever applied.
4. Repeat choosing KEEP; EXPECT: seal stays, snapshot sidecar remains,
   message documents the later-restore path.

### M3 — Publisher survival across a real app update (FR-03, SEC-02)

1. Bind a publisher rule to a signed app; update the app (new binary
   version at the same path).
2. EXPECT: FileMonitor re-hash loop re-validates (10-min cadence), the
   path filter re-materializes without a prompt; corrupt the binary
   signature -> drop-out + log entry (SEC-02 trigger).

### M4 — i18n sweep (NFR-05)

1. Switch UI language; verify every composite-facing string renders
   through the localization pipeline (no hardcoded English leaks).

### M5 — DHCP/CryptSvc continuity while locked (FR-06)

1. Engage Lockdown on a live machine.
2. EXPECT: DHCP renewals and CryptSvc operations continue (survival
   rules functional); outbound from other apps is blocked by the seal.

## Gate record (T016, OPS-01/OPS-03)

- `goldfish check` pre-merge gate: **local pre-merge** (CI not yet
  available — OPS-01). Last full-chain run for this branch: exit 0 at the
  r5 approval (see RESUME.md verification record); re-run is REQUIRED
  after the 2026-11-10 fix wave (S3/S4/port-swap + T007) before any PR
  merge. Owner-run: `python tools/goldfish_check_all.py` (from the chain
  root) or the upstream single-design check per round.
- Monthly upstream rebase window: FIRST WINDOW SCHEDULED 2026-12-01
  against henrypp v3.9.x; outcome to be recorded here (OPS-03, RSK-02).
- GPG-only interim release procedure: documented pending the Authenticode
  decision (OPS-02; blocked on the owner's PFX re-key).

## /W4 + /analyze status (T014, NFR-02/SEC-05)

- x64 Release `/W4`: **clean (zero warnings)** across all composite files
  (2026-11-10 wave; composite_lockdown.c required 6 fixes to reach zero).
- `/analyze` pass (2026-11-10, RunCodeAnalysisOnce): **executed**. Caught a
  REAL defect the compiler missed: three string builders passed as
  uninitialized pointers into `_r_obj_initializestringbuilder` (lockdown +
  packs) - writes through a garbage pointer on first engage; fixed by
  stack-allocating the builder struct. All composite-file findings fixed
  except ONE documented residual: composite_eventlog.c(196) C6387 param
  contract nit in T002-era code (in-body NULL init present; pre-existing).
  vendor/routine findings: upstream code, out of scope (DEC-01).
- Release inventory (unchanged binary set + <= 8 MB): to be asserted by
  the release job when packaging lands (vision tracker row 12).


---

# Manual procedures + gate record (T013/T016, 2026-11-10 wave)

## Manual procedures (OPS-04, SEC-03, FR-03, NFR-05, FR-06)

### M1 - GPO-locked fallback VM (RSK-01, FR-01)

1. VM with a GPO disabling the `Audit Filtering Platform Connection`
   subcategory and/or blocking `SCENoApplyLegacyAuditPolicy` changes.
2. Enable composite prompting.
3. EXPECT: prompt-degradation state surfaces (never silent), the
   FwpmNetEventSubscribe fallback engages automatically.

### M2 - Uninstall revert, before/after (SEC-03, FR-06)

1. Enable composite audit + Lockdown; change a firewall default manually
   while engaged.
2. Run `-uninstall` with confirmation; choose RELEASE (default).
3. EXPECT: audit subcategory restored to recorded priors; lockdown
   snapshot restored exactly; survival rules removed; never an
   unconditional ALLOW.
4. Repeat choosing KEEP: seal stays, snapshot sidecar remains.

### M3 - Publisher survival across a real app update (FR-03, SEC-02)

Bind a publisher rule to a signed app, update the binary; EXPECT
re-validation via the FileMonitor loop without a prompt; corrupt the
signature -> drop-out + log (SEC-02 trigger).

### M4 - i18n sweep (NFR-05)

Switch UI language; composite strings render through the localization
pipeline (tray/status composite surfaces currently literal English -
regenerate translations before release).

### M5 - DHCP/CryptSvc continuity while locked (FR-06)

Engage Lockdown on a live machine: DHCP renewals and CryptSvc operations
continue (survival rules), other outbound blocked by the seal.

## Gate record (T016, OPS-01/OPS-03)

- goldfish gate re-run 2026-11-10 after the S3/S4/port-swap/T007/T008
  wave: **0 findings, exit 0**.
- Monthly upstream rebase window: FIRST WINDOW 2026-12-01 against
  henrypp v3.9.x; outcome recorded here.
- GPG-only interim release procedure: pending the Authenticode re-key
  decision (OPS-02).

## /W4 + /analyze status (T014, NFR-02/SEC-05)

- x64 Release `/W4`: **clean (zero warnings)** across all composite
  files (2026-11-10 wave).
- `/analyze` executed 2026-11-10 (RunCodeAnalysisOnce): caught a REAL
  defect - three string builders passed as uninitialized POINTERS into
  `_r_obj_initializestringbuilder` (lockdown + packs; writes through a
  garbage pointer on first engage) - fixed by stack-allocating
  `R_STRINGBUILDER`. All composite findings fixed except ONE documented
  residual: composite_eventlog.c(196) C6387 param-contract nit in
  T002-era code. vendor/routine findings: upstream, out of scope (DEC-01).
- Release inventory (unchanged binary set + <= 8 MB): release job scope
  (vision tracker row 12).
