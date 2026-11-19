# Handoff: Hardening Round 1 (Trust-Boundary Fixes)

> Generated from `docs/specs/hardening-round-1/design.md` revision
> `2026-11-06-r4`, approved by the design owner on 2026-11-06 (DEC-03 B+
> decision recorded; FR-04 technical choice delegated by the design owner
> and resolved to de-elevated launch). This is an adapter, not a second
> specification: the design stays canonical; this file carries it into
> spec-driven execution. Prefer linking to the design's canonical sections
> over copying prose.

## Problem and intended outcomes

simplewall can silently keep no visible state when default-deny filters
fail to install, trust an attacker-writable internal ruleset, execute
attacker-config binaries elevated, and hold unused privileges for life.
Success is observable: degradation shows as a tray/status state (not only
log lines), a planted internal ruleset is ignored and logged, no
user-config binary ever runs elevated, and the process token at idle
carries no privilege without an in-tree consumer.

## In scope and out of scope

- In scope: `src/` only (wfp.c, profile.c, db.c, log.c, messages.c,
  main.c, helper.c, notifications.c) — survey findings #1–#8 and #10.
- Out of scope: `routine` submodule (separate audit), UI redesign, new
  features, profile-format changes, DPAPI migration (RSK-01), main-window
  message surface (RSK-04), wufix redesign (RSK-03), signed rule packages
  (planned Round 2, per DEC-03).

## User journeys and behavior

1. A global BLOCK filter fails to add (src/wfp.c:1829-1836): the failure
   aggregates into a degraded-enforcement flag surfaced on tray + status
   bar, with one aggregated log entry per apply (FR-01, SEC-01, OPS-01).
2. A same-user process plants a modified `profile_internal.xml` with a
   recomputed self-hash (src/profile.c:1545-1559, src/db.c:594): the app
   uses the compiled-in resource only, logs the foreign file as ignored,
   and "Internal rules" is removed from update components (FR-03, SEC-02).
3. A same-user process points `LogViewer` at a malicious binary
   (src/messages.c:1877-1909): the viewer launches de-elevated via the
   shell token, so the path executes at the attacker's own privilege
   level; delegation failure refuses and logs (FR-04, SEC-03).
4. A same-desktop process posts `WM_COMMAND` (KILL / special rules) to
   the notification window during the safety window or while hidden
   (src/notifications.c:1349-1355, 1172-1229): every action-bearing
   branch is gated like ALLOW/BLOCK already are (FR-07, SEC-05).
5. A crafted `WM_NOTIFICATION` carries a bogus `lparam`
   (src/main.c:2151): the object is re-acquired through the apps-table
   lookup; unknown pointers are ignored and logged (FR-08).

## Acceptance criteria

Distinguished from requirements: these are the observable checks.

- Given a planted internal-rules file with bumped version/timestamp,
  when the app loads, then the compiled-in resource wins, the foreign
  file is logged as ignored, and no planted rule applies (FR-03).
- Given a helper process posting KILL / special-rules `WM_COMMAND`
  during the safety window or while hidden, when the message arrives,
  then no process is killed and no rule is created (FR-07).
- Given `WM_NOTIFICATION` with a bogus `lparam`, when the message is
  processed, then no crash and no reference to unknown memory; the
  pointer is ignored and logged (FR-08).
- Given `LogViewer` set to an attacker-written binary, when the user
  opens the log, then the launched process is medium-IL (Process
  Explorer check); with no unelevated shell, the launch is refused and
  logged (FR-04).
- Given an idle elevated process, when its token is inspected, then
  SE_DEBUG is absent and SE_INC_BASE_PRIORITY alone is present
  (FR-05, SEC-04).
- Given a wufix enable followed by disable, when ImagePath is inspected,
  then the original value is restored, and a servicing-changed value is
  never overwritten (FR-06, DATA-01).
- Given a pre-existing log file with a default ACL, when the app starts,
  then its ACL is migrated to user + admins only (FR-09, SEC-06).
- Given a failed global-filter add, when rules apply, then tray and
  status reflect the degraded state and one aggregated error entry
  exists (FR-01, OPS-01) — manual procedure per RSK-00.
- Given the MSVC build, when touched files compile with `/W4` +
  `/analyze`, then warnings are clean (NFR-02).

## Constraints and quality attributes

- Zero UX regression on paths that never fail (NFR-01).
- MSVC build stays green; system APIs only; no new dependencies
  (NFR-02).
- No measurable latency added to rule-apply paths (NFR-03).
- Packet log readable only by current user + administrators (SEC-06).
- No measurable latency from privilege enable/drop helpers on their
  paths (supports FR-05).

## Approved decisions

- DEC-01: scope is src/ only; the routine submodule is audited
  separately.
- DEC-02: degraded state reuses existing error-plumbing style (global
  flag + tray/status + one aggregated log entry); successful re-apply
  clears it, restart resets it.
- DEC-03: variant B+ — on-disk internal-rules override removed (compiled
  -in resource only, foreign file logged), "Internal rules" unregistered
  from update components; signed rule packages are the planned Round 2.
- DEC-04: LogViewer launches de-elevated (shell-token delegation);
  refusal on delegation failure; signature gating rejected
  (CVE-2020-0601 history + unsigned-editor UX break).
- DEC-05: unused SE_* privileges dropped entirely (no in-tree consumer);
  SE_INC_BASE_PRIORITY stays; SE_DEBUG on-demand only if a real consumer
  exists in the kill path.
- DEC-06: profile "encryption" kept as-is this round, documented as
  obfuscation.

## Risks and open questions

- RSK-00: accepted as a documented manual procedure this round;
  FR-01/FR-02 verification automation is a Round 2 candidate
  (owner: fork maintainer).
- RSK-01: hardcoded profile key accepted — no secrets stored; DPAPI
  deferred with a resolution gate at Round 2 planning (owner: fork
  maintainer).
- RSK-02: runtime internal-rules updates stop working — accepted;
  resolution gate: refresh via build script or fork releases until
  signed packages land (owner: fork maintainer).
- RSK-03: wufix redesign out of scope — accepted; this round fixes only
  ImagePath preservation (owner: fork maintainer).
- RSK-04: main-window message surface deferred — accepted as residual;
  gate: the `is_postmessage` pattern (src/main.c:1336,1515,1548) is the
  building block (owner: fork maintainer).
- RSK-05: accepted — user profile.xml and LogPath are trusted as
  user-controlled state (residual of the product's threat model;
  owner: design owner).

## Traceability Key

| Key | Meaning |
| --- | --- |
| FR-01 | global-filter add failures aggregate into a degraded-enforcement flag surfaced on tray and status bar |
| FR-02 | transaction-start becomes a tri-state (TXN_STARTED / TXN_IN_PROGRESS / TXN_FAILED); on FAILED: shared lock released, FwpmTransactionAbort0 called only if a transaction actually opened, commit never runs, apply aborts with an error; the applying-never-sticks invariant holds |
| FR-03 | on-disk internal-rules override never preferred (compiled-in resource only, per DEC-03 B+); foreign file logged as ignored; rules removed from update components |
| FR-04 | LogViewer launches de-elevated via the shell token (Explorer delegation); delegation failure ⇒ refuse + log; no signature/hash gating |
| FR-05 | startup enables only privileges with in-tree consumers; SE_DEBUG (if needed) is enable-on-demand around the kill path and dropped after |
| FR-06 | wufix preserves the original service ImagePath before modification and restores it on disable; restore happens only if the current value still equals the value we wrote (else warn + leave) |
| FR-07 | every notification-window action branch (KILL, special rules) is gated by the same enabled/visible check as ALLOW/BLOCK |
| FR-08 | WM_NOTIFICATION re-acquires the log object via the apps-table lookup; unknown pointers are ignored and logged |
| FR-09 | connection log file created with an explicit SECURITY_ATTRIBUTES (user + admins only) and one-time SetSecurityInfo migration applied to pre-existing log files at startup |
| SEC-01 | enforcement degradation is visible as a state, not only as log lines |
| SEC-02 | an attacker-writable internal-rules file is never preferred over the compiled-in resource |
| SEC-03 | no binary from user-writable config ever executes with elevated privileges |
| SEC-04 | the process holds no privilege without an in-tree consumer, and SE_DEBUG only inside its use window |
| SEC-05 | notification actions cannot be triggered during the safety window or while hidden |
| SEC-06 | the packet log is readable only by the current user and administrators |
| NFR-01 | zero UX regression on paths that never fail |
| NFR-02 | MSVC build stays green with existing dependencies only |
| NFR-03 | no measurable latency added to rule-apply paths |
| DATA-01 | original service ImagePath is persisted before modification and restorable |
| OPS-01 | degraded enforcement writes one aggregated, greppable error-log entry per apply |
| DEC-01 | scope limited to src/ (+ build.bat under DEC-03-A); routine submodule separate |
| DEC-02 | degraded state reuses existing error-plumbing pattern, no new subsystem |
| DEC-03 | internal-rules trust: variant B+ — override removed, updater rules component unregistered; signed packages = Round 2 |
| DEC-04 | LogViewer launches de-elevated (shell-token delegation, refuse+log on failure); signature gating rejected (CVE-2020-0601 history + unsigned-editor UX break) |
| DEC-05 | unused SE_* privileges dropped; SE_INC_BASE_PRIORITY stays; SE_DEBUG on-demand only if a real consumer exists |
| DEC-06 | profile "encryption" kept as-is this round, documented as obfuscation |
| RSK-00 | FR-01/FR-02 verification is a documented manual procedure this round (no BFE injection harness); automation = Round 2 candidate |
| RSK-01 | hardcoded profile key accepted (no secrets stored); DPAPI deferred |
| RSK-02 | runtime internal-rules updates stop working (accepted); refresh via build script or fork releases; signed packages = Round 2 |
| RSK-03 | wufix redesign out of scope; only ImagePath preservation fixed |
| RSK-04 | main-window message surface and confirmation-dialog exposure deferred to a later round |
| RSK-05 | user profile.xml and LogPath trusted as user-controlled state (residual, by threat model) |
