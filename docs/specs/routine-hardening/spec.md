# Specification: Round 2 — Routine Hardening & Secure Updater

Derived from `handoff.md` (design revision `2026-11-06-r2`).

## User stories

- **US1:** As a user, a MITM on the network cannot impersonate the update
  feed: TLS failures abort, the manifest signature is verified against a
  key embedded in the binary, and versions never go backwards
  (FR-01, FR-02, FR-03, SEC-01).
- **US2:** As a user, a downloaded update artifact cannot be swapped or
  redirected between download and use — it is hashed on an exclusive
  handle, atomically renamed, and reparse-proof (FR-04, FR-07, SEC-02).
- **US3:** As the fork maintainer, the vendored library is pinned in-tree
  with compile-time guards on the exact API shapes the fork calls, so the
  build cannot drift from the audited contract (FR-09, FR-10, NFR-03).
- **US4:** As the fork maintainer, upstream library fixes merge into the
  vendor copy manually and deliberately (RSK-03 posture, DEC-01).
- **US5:** As a user, the updater still works exactly as before when
  everything is healthy — same UX, now fail-closed underneath (NFR-01,
  OPS-01).

## Acceptance scenarios

- **AS1 (US1):** Given a self-signed MITM, when the update check runs,
  then it aborts and logs; no ignore-retry occurs (FR-01, SEC-01).
- **AS2 (US1):** Given a reworked or rollbacked manifest, when
  verification runs, then invalid signature and lower versions are
  rejected before any download (FR-03, SEC-01).
- **AS3 (US2):** Given a byte-flipped artifact, when integrity runs,
  then the sha256 mismatch drops it and logs (FR-03, OPS-01).
- **AS4 (US2):** Given a junction planted in the cache dir, when files
  open, then traversal does not follow it; the cache dir DACL is
  restrictive (FR-07, SEC-02).
- **AS5 (US2):** Given a racing writer during download, when the rename
  executes, then the moved bytes are exactly the hashed bytes (FR-04).
- **AS6 (US3):** Given the vendored build, when it compiles, then
  `C_ASSERT` guards pass for both fork call shapes and the build is
  green (FR-09, FR-10, DEC-04, NFR-03).
- **AS7 (US4):** Given the vendored snapshot, when the include path
  resolves, then no reference to a sibling/float-on-master routine
  remains in the project (FR-09, DEC-01).
- **AS8 (US5):** Given a healthy check against the fork feed, when all
  verifications pass, then the updater completes its existing UX flow
  (NFR-01).
- **AS9 (US1):** Given a registry value growing between probe and read,
  when the query runs, then the bounded retry loop prevents the
  overflow (FR-05).
- **AS10:** Given a concurrent settings write racing a settings read,
  when both run, then the config object body is referenced under its
  protecting lock and no use-after-free occurs (FR-06).
- **AS11:** Given the LOW-hygiene class (zero-length REG_SZ, self-swap
  reference, unquoted installer args, oversized INI value), when each
  path runs, then guards hold and values are bounded with a documented
  truncation limit (FR-08).

## Quality attribute scenarios

- **QA1:** No new third-party crypto dependency — CNG BCrypt ECDSA P-256
  only (NFR-02, DEC-02).
- **QA2:** Signing keys: private key never in the repo; generation and
  rotation documented with a key-epoch field (DATA-01, RSK-02).
- **QA3:** Bootstrap self-test (sign→verify round-trip, tampered-vector
  failure) must pass before the updater is enabled (RSK-04, DEC-05).

## Success criteria

All acceptance scenarios pass; the chain's requirement keys all have
implementing tasks; the build gate on the owner machine stays green.
