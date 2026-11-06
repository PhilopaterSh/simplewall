# Design: Hardening Round 1 (Trust-Boundary Fixes)

> Revision `2026-11-06-r4` — consolidated: goldfish review + DEC-03 B+
> decision (2026-11-06) + senior review (6 items) + FR-04 resolved to
> de-elevated launch (owner delegated the technical choice to the design
> owner after an internet-validated comparison; 2026-11-06). Final
> approval gate: on the complete chain before implementation.

## Problem and intended outcomes

simplewall's C codebase is memory-safe by discipline (bounded string APIs,
refcounted objects), but the 2026-11-06 code survey found the real gaps sit
at trust boundaries. Today the product can silently keep no degraded-state
signal when global default-deny filters fail to install, prefer an
attacker-writable internal ruleset, execute attacker-influenced binaries
from an elevated context, and hold powerful privileges for its whole
lifetime. This round makes enforcement degradation **visible as a state**,
shrinks the elevated attack surface, and closes the cheap trust-boundary
holes — without changing UX for the happy path.

Intended observable outcomes:

1. If a global default-deny filter fails to install, the failure is
   aggregated into a visible degraded-enforcement state (tray/status) on
   top of the per-failure log entries that already exist today
   (FR-01, SEC-01, OPS-01).
2. A same-user, non-elevated process can no longer (a) plant an
   internal ruleset the elevated app will trust, (b) point the log viewer
   at an arbitrary unverified binary, (c) trigger process-kill /
   rule-minting via notification-window messages, or (d) crash the
   elevated app via a crafted log-pointer message
   (FR-03, FR-04, FR-07, FR-08).
3. The elevated process no longer enables privileges it never uses, and
   holds SE_DEBUG only inside the short kill-path window that may need it
   (FR-05, SEC-04).

## In scope and out of scope

- **In scope:** `src/` C code only — wfp.c, profile.c, db.c, log.c,
  messages.c, main.c, helper.c, notifications.c. No new libraries; all
  fixes use system APIs already available to the project.
- **Out of scope:** the `routine` submodule (not present in-tree; its
  transport/config/deploy code is a separate audit — this is why no
  runtime hash-*recording* design exists in this round), UI redesign, new
  features, profile-format changes, DPAPI migration of the "encrypted"
  profile mode (RSK-01), localization changes, main-window message
  surface (RSK-04).

## User journeys and behavior

1. Administrator applies rules; suppose `FwpmFilterAdd0` fails for a
   fallback BLOCK filter (src/wfp.c:1829-1836). Today: one log entry
   (src/wfp.c:803), no state change. Now: the failure aggregates into a
   degraded-enforcement flag; the tray icon and status bar reflect it
   until rules re-apply successfully (FR-01, DEC-02).
2. An attacker with the same user account writes a modified
   `profile_internal.xml` with a recomputed self-hash (src/db.c:540,594).
   Today: the elevated app prefers it whenever its parsed version/timestamp
   beats the resource's (src/profile.c:1545-1559). Now: the on-disk
   override preference is removed — the compiled-in resource is the only
   internal ruleset source, "Internal rules" is removed from the runtime
   update component list (src/main.c:2029) so no untrusted file is even
   downloaded, and any foreign on-disk file is logged as ignored
   (FR-03, SEC-02, DEC-03).
3. A non-elevated process sets the `LogViewer` config value to a malicious
   path (launch happens in the elevated process at src/messages.c:1877-1909
   via `_app_getlogviewer`, src/log.c:93-111). Now: the viewer never runs
   elevated — the app delegates the launch to the user's shell token
   (Explorer), so an attacker-controlled path executes at the attacker's
   own privilege level and gains nothing; if delegation fails, the launch
   is refused and logged (FR-04, SEC-03, DEC-04).
4. A same-desktop process posts `WM_COMMAND` to the notification window
   during the 900 ms safety window (or while hidden) to kill a process or
   mint a PERMIT rule (ungated branches: src/notifications.c:1349-1355,
   1172-1229; ALLOW/BLOCK already gate at 1343). Now: every action-bearing
   branch is gated by the same enabled/visible check (FR-07, SEC-05).
5. A crafted `WM_NOTIFICATION` arrives with a bogus `lparam`
   (src/main.c:2151 refcounts it blindly). Now: the object is re-acquired
   through the same apps-table lookup the notification flow already uses
   (`_app_notify_getobject`-style, src/notifications.c:188); unknown
   pointers are ignored and logged (FR-08).

## Constraints and quality attributes

- Zero UX regression for users who never hit a failure path (NFR-01).
- MSVC build of `simplewall.vcxproj` stays green; no new dependencies
  (NFR-02).
- Privilege enable/drop helpers add no measurable latency to rule-apply
  paths (NFR-03).
- The packet log file is creatable/readable only by the current user and
  administrators (SEC-06, FR-09).

## Proposed decisions

*(pending approval; DEC-03 variant is the approval-gate choice)*

- DEC-01: scope is src/ only (+ `build.bat` under DEC-03-A); the routine
  submodule is audited separately.
- DEC-02: degraded enforcement reuses the existing error-plumbing style —
  a global flag set by `_wfp_createglobalfilters` failures, reflected on
  tray icon + status text + one aggregated log entry — not a new
  notification subsystem. Lifecycle: successful re-apply clears the flag;
  process restart resets it.
- DEC-03 (decided by the design owner, 2026-11-06): variant B+ — the
  on-disk `profile_internal` override preference is removed (compiled-in
  resource is the only internal source; a foreign on-disk file is logged
  as ignored) and "Internal rules" is unregistered from the update
  component list. Secure runtime updates return in Round 2 as signed rule
  packages (embedded public key, signature + anti-rollback verification,
  Portmaster/TUF-style); not designed in this round.
- DEC-04: `LogViewer` never runs elevated. The elevated app delegates the
  launch to the user's shell (Explorer token, Raymond-Chen pattern:
  IShellDispatch2::ShellExecute or token duplication + CreateProcessWithTokenW);
  on delegation failure (no unelevated shell) the launch is refused and
  logged. No signature or hash gating is required: an attacker-chosen
  binary runs at the attacker's own privilege level. Signature-based
  gating was rejected after review (CVE-2020-0601/CVE-2013-3900 history,
  unsigned-editor UX break).
- DEC-05: startup drops SE_SECURITY, SE_TAKE_OWNERSHIP, SE_BACKUP,
  SE_RESTORE, SE_DEBUG entirely (no in-tree consumer: signature checks and
  wufix need admin, not privileges — verified); SE_DEBUG becomes
  enable-on-demand around the kill path's PROCESS_TERMINATE opens only if
  implementation confirms a real need, else it is dropped too;
  SE_INC_BASE_PRIORITY stays (genuinely used for process priority,
  src/main.c:1825,1839).
- DEC-06: the "encrypted" profile mode keeps its current format this round
  (RSK-01); a code comment marks it as obfuscation-only.

## Verification approach

Honest split between automatable and manual checks (seeds the spec's
acceptance criteria):

- **Build gate (automated):** MSVC build of `simplewall.vcxproj` clean at
  `/W4` with `/analyze` on every touched file (NFR-02).
- **FR-03 (automated smoke):** plant a modified `profile_internal.xml`
  with a bumped version/timestamp in the config dir; the app must use the
  compiled-in resource, log the foreign file as ignored, and never apply
  the planted rules.
- **FR-07 (automated smoke):** from a helper process, PostMessage
  `WM_COMMAND` (KILL and special-rules IDs) to the notification window
  during the safety window and while hidden; no process kill and no rule
  creation may occur.
- **FR-05 (automated check):** at idle, the process token contains
  SE_INC_BASE_PRIORITY only; SE_DEBUG is absent and appears solely within
  an active kill-path window (asserted via a debug-log line at
  enable/drop).
- **FR-01 / FR-02 (manual, documented procedure):** BFE failure injection
  needs a test harness; acceptance is a documented manual procedure plus
  code review against the tri-state contract and the abort-on-failure
  path.
- **FR-04 (manual):** set `LogViewer` to an attacker-written binary; the
  launched process must be medium-IL (verified with Process Explorer);
  with no unelevated shell available, the launch is refused and logged.

- RSK-01: hardcoded profile key (survey finding #9) accepted this round —
  no credential-like data is stored; DPAPI migration deferred.
- RSK-02: under DEC-03 B+, runtime rules updates stop taking effect in
  this fork; accepted — the fork owner refreshes rules via the build
  script (`build_simplewall_rules.bat`, needs the `builder` sibling repo)
  or ships new fork releases. Signed rule packages are the planned Round 2
  replacement.
- RSK-03: wufix redesign stays out of scope; this round only adds
  ImagePath preservation/restoration (DATA-01, FR-06).
- RSK-04: the main window also accepts state-changing `WM_COMMAND` from
  same-desktop processes (e.g. IDM_TRAY_START, src/main.c:3298) and the
  confirmation dialog is answerable by the same attacker; honest
  mitigation needs a message-origin design — deferred to a later round.
  The existing `is_postmessage` self-marker pattern
  (lparam == WM_APP; src/main.c:1336,1515,1548) is the natural building
  block for that round.
- RSK-05: the user profile.xml (arbitrary PERMIT rules) and the
  user-config `LogPath` target are trusted by design as user-controlled
  state; treated as residual risk of the product's threat model, not a
  defect.

## Risks and open questions

- RSK-00: verification of FR-01/FR-02 relies on a documented manual
  procedure (no BFE failure-injection harness this round); automating it
  is a Round 2 candidate.

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
| RSK-01 | hardcoded profile key accepted (no secrets stored); DPAPI deferred |
| RSK-00 | FR-01/FR-02 verification is a documented manual procedure this round (no BFE injection harness); automation = Round 2 candidate |
| RSK-02 | runtime internal-rules updates stop working (accepted); refresh via build script or fork releases; signed packages = Round 2 |
| RSK-03 | wufix redesign out of scope; only ImagePath preservation fixed |
| RSK-04 | main-window message surface and confirmation-dialog exposure deferred to a later round |
| RSK-05 | user profile.xml and LogPath trusted as user-controlled state (residual, by threat model) |
