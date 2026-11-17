# Specification: Security Fixes — the 2026-11-17 audit remediation

Derived from design.md r2 (owner directive recorded; goldfish review APPROVE-WITH-CHANGES integrated).

## User stories

- US1: As the user I click "install now" and the elevated installer that runs is the exact verified artifact - no same-user process can swap it in the window (FR-01, FR-02, DEC-01, DEC-02).
- US2: As the owner I trust the composite accountability sidecars because the config-dir DACL actually applies the intended policy at every startup (FR-03, DEC-03).
- US3: As a same-desktop process I can no longer mint a PERMIT rule through the notification window's editor command outside the safety window (FR-04, DEC-04).
- US4: As a future maintainer I read update_key.h and get the CORRECT byte-order convention - no regression bait (FR-05, DEC-05).

## Acceptance scenarios

- AS1: Given the cached installer and a live feed hash, when the install path runs, then the artifact is opened write-excluding, hash-verified on the held handle, and the elevated install spawns only on match (FR-01, DEC-01).
- AS2: Given a byte flipped in the cached installer after download, when the install path runs, then the hash re-verify fails, the artifact is deleted, and nothing is executed (SEC-01).
- AS3: Given a manifest without a hash for the installer component, when the install path runs, then the install refuses fail-closed (FR-02, DEC-02).
- AS4: Given a writer (e.g. a same-user process) attempting to open the held installer for write during the verify+exec window, when it opens the file, then it receives a sharing violation (FR-01, DEC-01).
- AS5: Given the app starting elevated, when _app_integrity_hardenacl runs, then the profile dir DACL = Administrators FULL + SYSTEM FULL + process-token user READ, applied PROTECTED, and failures log non-fatally with the exact API name (FR-03, DEC-03, NFR-01).
- AS6: Given a WM_COMMAND IDM_OPENRULESEDITOR arriving while the proxy control IDC_ALLOW_BTN is disabled, when the branch runs, then it refuses and rate-limited-logs (FR-04, DEC-04).
- AS7: Given update_key.h read by a future maintainer, then the comment states BIG-endian verbatim matching rapp.c + the CNG bench (FR-05, DEC-05).
- AS8: Given the six routed audit minors, when docs/BACKLOG.md is read, then they are recorded with the audit evidence location (design r2 BACKLOG deliverable).

## Imported keys coverage (composite/routine-hardening chains)

- FR-12 (imported, composite chain): repaired by T002 - the runtime-broken DACL is this chain's direct target (AS5).
- FR-07 (imported, hardening-round-1 chain): the branch it claimed to gate is gated by T003 (AS6) - closing the round-1 contradiction.
- NFR-02 (imported, hardening-round-1 chain): the /W4+/analyze build gate is ROUTED TO BACKLOG by this chain (out of scope here; recorded in the audit minors entry).
- SEC-05 (imported, composite design): untouched - all fixes hold handles, none spawn processes (binding constraint on T001/T002/T003).

## Success criteria

1. All four fixes implemented on feat/security-fixes; CI-dispatch green; merged.
2. No regression: the CI launch test passes; NSIS install round verified in the sandbox lane (RSK-01) before re-release.
3. goldfish check exit 0 for this chain; artifacts 0 violations.
4. The three MAJORs are closed on master; re-release (G-3) becomes a build+sign+publish step.
