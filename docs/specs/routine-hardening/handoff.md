# Handoff: Round 2 — Routine Hardening & Secure Updater

> Generated from `docs/specs/routine-hardening/design.md` revision
> `2026-11-06-r2`, approved by the design owner on 2026-11-06. This is an
> adapter, not a second specification: the design stays canonical; prefer
> linking to its canonical sections over copying prose.

## Problem and intended outcomes

The fork's support library ships an MITM-exploitable update chain (TLS
CA-ignore retry, unsigned server-controlled URLs, download TOCTOU,
elevated installer exec) and its public master ABI no longer matches the
consumer. Success is observable: the updater works end-to-end against
the fork's own signed feed, every verification failure is fail-closed
and logged, and the vendored library is pinned in-tree with compile-time
API guards.

## In scope and out of scope

- In scope: vendored `vendor/routine/` copy; audit patches F1–F6 plus the
  four LOW hygiene fixes; CNG ECDSA P-256 detached-signature manifest
  scheme; fork feed bootstrap tooling (keygen/signer/self-test);
  `C_ASSERT` guards; include-path update.
- Out of scope: upstream binaries; update UI/UX changes; TUF/WinSparkle/
  Omaha adoption; RSK-04 main-window messages (separate round); rules/
  language package unification (Round 3 — RSK-05).

## User journeys and behavior

1. Update check: manifest fetched over HTTPS from the pinned fork
   release origin; TLS secure failure aborts with no ignore-retry; the
   detached `manifest.sig` verifies against the embedded public key;
   version monotonicity enforced (FR-01, FR-02, FR-03).
2. Artifact landing: fetched from wherever the release host serves it,
   untrusted until the manifest sha256 passes; exclusive handle through
   download+hash+rename; atomic `FileRenameInformation`; reparse-proof
   opens; restrictive cache-dir DACL (FR-04, FR-07, SEC-02).
3. Failure paths: every transport/integrity/version failure is logged
   fail-visibly and never degrades into "use it anyway" (OPS-01,
   SEC-01).

## Acceptance criteria

Distinguished from requirements: these are observable checks.

- Given a MITM with a self-signed certificate, when the updater runs,
  then the check aborts and logs; no retry-with-ignore occurs (FR-01,
  SEC-01).
- Given a tampered artifact (byte flipped), when integrity runs, then
  the sha256 mismatch drops the artifact and logs (FR-03, SEC-01).
- Given a rollbacked manifest (lower version), when verification runs,
  then it is rejected (FR-03).
- Given a reworked manifest with an invalid signature, when verification
  runs, then it is rejected before any download (FR-03, DEC-05).
- Given a junction planted in the cache dir, when the updater opens
  files, then traversal does not follow it (FR-07, SEC-02).
- Given the fork's dependency APIs, when the vendored build compiles,
  then `C_ASSERT` guards pass for both fork call shapes (FR-10, DEC-04).
- Given a self-test run of the bootstrap signer, when vectors execute,
  then sign→verify round-trips and a tampered vector fails (RSK-04).
- Given a normal update check against the fork feed, when all checks
  pass, then the updater completes its existing UX flow (NFR-01).

## Constraints and quality attributes

- Updater fully functional in the fork against the fork's signed feed
  (NFR-01).
- No new third-party crypto dependency — Windows CNG ECDSA P-256 only
  (NFR-02).
- MSVC build green with the vendored routine aligned to the fork ABI
  (NFR-03).

## Approved decisions

- DEC-01: routine vendored in-tree (`vendor/routine/`), pinned snapshot;
  no float-on-master submodule.
- DEC-02: CNG ECDSA P-256 signatures; vendored Ed25519 alternative
  rejected for now.
- DEC-03: fork feed = PhilopaterSh releases + `manifest.json` +
  `manifest.sig`; manifest origin pinned; artifact URLs untrusted until
  sha256 passes (GitHub redirects acceptable by design); upstream feed
  dropped.
- DEC-04: vendored routine adopts the fork ABI — guarded contract: 5-arg
  `_r_sys_setprocessprivilege(hwnd, ...)` and
  `_r_fs_createfile(&handle, &path, ...)` (consumer call sites
  src/notifications.c:464, src/main.c:1837, src/db.c:912, src/log.c:100).
- DEC-05: canonical detached signature — raw 64-byte r||s over exact
  manifest.json bytes; embedded `BCRYPT_ECDSA_PUBLIC_P256_MAGIC` key;
  verify on the precomputed SHA-256 digest.

## Risks and open questions

- RSK-01: upstream auto-tracking stops — accepted; merges are manual
  (owner: fork maintainer).
- RSK-02: signing key loss blocks updates until rotation — accepted;
  key-epoch field + regeneration runbook documented (owner: design
  owner).
- RSK-03: accepted — upstream routine fixes merge manually into the
  vendor copy; audit report is the patch baseline (owner: fork
  maintainer).
- RSK-04: gate — CNG normalization proven by test vectors before
  enable; bootstrap self-test must pass (owner: implementation).
- RSK-05: rules/language unification deferred to Round 3 — accepted;
  Round-1 fail-safe posture stays shipped behavior, consciously
  superseding Round-1 DEC-03's Round-2 promise (owner: design owner).

## Traceability Key

| Key | Meaning |
| --- | --- |
| FR-01 | transport never ignores TLS secure failures; CA/CN/date errors abort the update |
| FR-02 | manifest fetched only over HTTPS from the pinned/validated manifest origin; artifact URLs untrusted until the manifest sha256 passes (GitHub redirects acceptable by design) |
| FR-03 | every artifact verified before use: detached ECDSA manifest.sig (raw r||s over exact manifest bytes) against the embedded public key + sha256 of the artifact + monotonic version |
| FR-04 | cache file held with an exclusive handle through the download+hash+rename window (FileRenameInformation on the open handle); re-open by path allowed only after integrity passes |
| FR-05 | variable-size registry queries use a bounded retry loop on ResultLength |
| FR-06 | config object body is referenced while holding the lock protecting it |
| FR-07 | update-path file opens use FILE_OPEN_REPARSE_POINT plus final-path verification; cache dir has a restrictive DACL |
| FR-08 | LOW-hygiene set: REG_SZ zero-length guard, swapreference order, quoted installer args, INI values bounded with a documented truncation limit |
| FR-09 | routine vendored and pinned in-tree; include path updated; no float-on-master |
| FR-10 | C_ASSERT arity/type guards exist for the consumer-dependency API list |
| SEC-01 | update chain fail-closed at transport, integrity, and version steps |
| SEC-02 | no attacker-writable path participates in the update chain (cache dir DACL) |
| NFR-01 | updater fully functional in the fork against the fork's signed feed |
| NFR-02 | no new third-party crypto dependency (CNG BCrypt ECDSA P-256) |
| NFR-03 | MSVC build green with vendored routine aligned to the fork ABI |
| DATA-01 | key generation/rotation runbook documented; private key never in repo |
| OPS-01 | every verification failure logged fail-visibly |
| DEC-01 | vendored in-tree routine (vendor/routine), pinned snapshot |
| DEC-02 | CNG ECDSA P-256 signatures (alternative: vendored Ed25519, rejected for now) |
| DEC-03 | fork feed = PhilopaterSh releases + signed manifest; upstream feed dropped; artifacts untrusted until sha256 |
| DEC-04 | vendored routine adopts the fork ABI with C_ASSERT guards on the two call shapes |
| DEC-05 | canonical detached signature: manifest.sig = raw 64-byte ECDSA P-256 (r||s) over exact manifest.json bytes; embedded BCRYPT_ECDSA_PUBLIC_P256_MAGIC key; verify on precomputed SHA-256 digest |
| RSK-01 | upstream auto-tracking stops (manual merges) |
| RSK-02 | signing key loss blocks updates until rotation (documented runbook) |
| RSK-03 | upstream routine fixes merged manually into the vendor copy |
| RSK-04 | CNG import/verify normalization proven by test vectors before updater enable |
| RSK-05 | rules/language unification deferred to Round 3; Round-1 fail-safe rules posture stays shipped behavior |
