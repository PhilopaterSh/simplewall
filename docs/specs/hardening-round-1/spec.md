# Specification: Hardening Round 1 (Trust-Boundary Fixes)

Derived from `handoff.md` (design revision `2026-11-06-r4`).

## User stories

- **US1:** As a user, when a global default-deny filter fails to install,
  I see a degraded-enforcement state on the tray and status bar so that
  "nothing is blocking" is never silent (FR-01, SEC-01, OPS-01).
- **US2:** As a user on a shared machine, a same-user process cannot plant
  an internal ruleset that my firewall trusts, because the compiled-in
  resource is the only internal source and foreign files are ignored and
  logged (FR-03, SEC-02).
- **US3:** As a user, my log viewer opens at my own privilege level, so a
  tampered viewer path can never hijack the firewall's elevation
  (FR-04, SEC-03).
- **US4:** As a user, my firewall does not hold privileges it never uses;
  powerful privileges exist only inside the short window that needs them
  (FR-05, SEC-04).
- **US5:** As a user, a fast double-click or a foreign window message
  cannot kill a process or mint rules for me (FR-07, SEC-05).
- **US6:** As a user, a crafted window message cannot crash or corrupt the
  firewall's log state (FR-08).
- **US7:** As a user, my connection log is readable only by me and
  administrators, including log files created by older builds (FR-09,
  SEC-06).
- **US8:** As the fork maintainer, wufix never destroys a service's
  original ImagePath and never restores a stale one (FR-06, DATA-01).

## Acceptance scenarios

- **AS1 (US1):** Given a failed global-filter add, when rules apply, then
  the tray and status bar show the degraded state, one aggregated error
  entry is written, and a successful re-apply clears the state
  (FR-01, SEC-01, OPS-01, DEC-02).
- **AS2 (US2):** Given a planted `profile_internal.xml` with a recomputed
  self-hash and bumped version, when the app loads, then the resource
  wins, the foreign file is logged as ignored, and no update component
  downloads internal rules anymore (FR-03, SEC-02, DEC-03).
- **AS3 (US3):** Given `LogViewer` pointed at an attacker binary, when the
  log is opened, then the process runs medium-IL; with no unelevated
  shell the launch is refused and logged (FR-04, SEC-03, DEC-04).
- **AS4 (US4):** Given an idle elevated process, when its token is
  inspected, then only SE_INC_BASE_PRIORITY is present; SE_DEBUG appears
  only inside an active kill-path window and is dropped after
  (FR-05, SEC-04, DEC-05).
- **AS5 (US5):** Given KILL or special-rules `WM_COMMAND` posted during
  the safety window or while hidden, when the message arrives, then no
  process is killed and no rule is created (FR-07, SEC-05).
- **AS6 (US6):** Given `WM_NOTIFICATION` with a bogus `lparam`, when it is
  processed, then the object is re-acquired via the apps-table lookup,
  unknown pointers are ignored and logged, and the app keeps running
  (FR-08).
- **AS7 (US7):** Given a fresh or pre-existing log file, when the app
  runs, then its ACL allows only the current user and administrators
  (FR-09, SEC-06).
- **AS8 (US8):** Given wufix enable then disable, when ImagePath is
  inspected, then the original value is restored only if the current
  value is still the one we wrote (FR-06, DATA-01, RSK-03).

## Quality attribute scenarios

- **QA1:** On every happy path (no failures), behavior and UI are
  unchanged from upstream (NFR-01).
- **QA2:** Touched files compile clean under `/W4` + `/analyze`; no new
  dependencies (NFR-02).
- **QA3:** Rule-apply latency is unchanged within measurement noise;
  privilege enable/drop helpers stay off the rule-apply path
  (NFR-03, FR-02).

## Success criteria

All acceptance scenarios pass (automated smoke where stated in the
design's Verification approach, documented manual procedures otherwise
per RSK-00); the MSVC build gate is green; no requirement key lacks an
implementing task.
