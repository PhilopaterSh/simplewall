# Implementation Plan: Hardening Round 1 (Trust-Boundary Fixes)

Derived from `spec.md`; preserves the approved decisions.

## Approach

- Scope discipline (DEC-01): every change below lands in `src/` only; the
  `routine` submodule stays untouched for a separate audit.
- **wfp.c first (the load-bearing fix):** convert `_wfp_transact_start`
  into a tri-state (TXN_STARTED / TXN_IN_PROGRESS / TXN_FAILED). Only
  TXN_FAILED releases the shared `lock_transaction` acquisition, calls
  `FwpmTransactionAbort0` if a transaction actually opened, and aborts
  the apply with an error; commit never runs on a failed or absent
  transaction (FR-02). Global-filter add results aggregate into a
  degraded flag cleared by a successful re-apply (FR-01, DEC-02).
- **Trust boundaries are one-line policy changes plus logging:** the
  internal-rules override preference is removed (FR-03, DEC-03), the
  "Internal rules" update component is unregistered (main.c:2029), and
  the LogViewer launch moves to shell-token delegation (FR-04, DEC-04)
  using the Raymond-Chen pattern; refusal on delegation failure.
- **Privilege minimization is startup deletion plus one on-demand
  helper:** drop SE_SECURITY/SE_TAKE_OWNERSHIP/SE_BACKUP/SE_RESTORE/
  SE_DEBUG at startup (no in-tree consumer), keep SE_INC_BASE_PRIORITY,
  and enable SE_DEBUG only if the kill path proves it needs
  PROCESS_TERMINATE on other users' processes, dropping it immediately
  after (FR-05, DEC-05).
- **Window-message hardening is gating, not redesign:** KILL and
  special-rules branches get the same `_r_ctrl_isenabled` gate
  ALLOW/BLOCK already have (FR-07); `WM_NOTIFICATION` re-acquires the
  object through the apps-table lookup instead of trusting `lparam`
  (FR-08).
- **File/registry hygiene:** explicit SECURITY_ATTRIBUTES on log
  creation plus a one-time `SetSecurityInfo` migration for pre-existing
  files (FR-09); wufix stores the original ImagePath and restores it
  only when the current value still matches what we wrote
  (FR-06, DATA-01).
- No profile-format changes: the "encrypted" mode keeps its format and
  gains an obfuscation-only comment (DEC-06).

## Verification strategy

- Build gate: `/W4` + `/analyze` clean on touched files (NFR-02).
- Automated smoke procedures from the design's Verification approach:
  planted internal file (FR-03), posted KILL/special-rules messages
  (FR-07), bogus `WM_NOTIFICATION` pointer (FR-08), idle-token privilege
  audit (FR-05).
- Manual documented procedures per RSK-00: degraded-state observation
  (FR-01, OPS-01), tri-state transaction contract review (FR-02),
  medium-IL viewer check (FR-04).
- Happy-path regression pass over rule apply, notifications, and log
  viewing (NFR-01, NFR-03).

## Risks carried forward

- RSK-00: FR-01/FR-02 verification stays manual this round; accepted by
  the design owner, automation is a Round 2 candidate.
- RSK-01: hardcoded profile key accepted (no secrets stored); DPAPI
  deferred.
- RSK-02: runtime internal-rules updates stop working; accepted —
  refresh via build script or fork releases until signed packages
  (Round 2) land.
- RSK-03: wufix redesign out of scope; accepted — only ImagePath
  preservation is fixed here.
- RSK-04: main-window message surface deferred to a later round;
  accepted — the `is_postmessage` self-marker pattern is the recorded
  building block.
- RSK-05: user profile.xml and LogPath are trusted user-controlled
  state; accepted residual of the threat model.
