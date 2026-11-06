# Implementation Plan: Round 2 — Routine Hardening & Secure Updater

Derived from `spec.md`; preserves the approved decisions.

## Approach

- **Vendor first (FR-09, DEC-01):** copy `routine/src` into
  `vendor/routine/`, update `simplewall.vcxproj` IncludePath from the
  sibling path, and align the two ABI shapes to the fork contract
  (DEC-04): `_r_sys_setprocessprivilege(hwnd, handle, privs, count,
  enable)` and `_r_fs_createfile(&handle, &path, ...)`. The vendored copy
  is the patch baseline for everything below.
- **Patch the audited findings in the vendor copy:**
  - F1 (FR-01): delete the `SECURITY_FLAG_IGNORE_UNKNOWN_CA` retry in
    `_r_inet_openurl` — secure failure aborts, logged.
  - F4 (FR-05): registry probe-then-read becomes a bounded retry loop on
    `ResultLength` (the unbounded copy lives at routine.c:15157).
  - F5 (FR-06): reference the config object body while holding the lock
    that protects it (rapp.c:1346-1366), closing the find-then-add gap.
  - F6 (FR-07): `FILE_OPEN_REPARSE_POINT` + `GetFinalPathNameByHandle`
    verification + restrictive DACL on the update cache directory.
  - F3 (FR-04): download holds an exclusive handle through
    download+hash+rename; atomic `FileRenameInformation`; re-open by path
    only after integrity passes.
  - F8/LOWs (FR-08): REG_SZ zero-length guard, swapreference order,
    quoted installer args, INI values bounded with documented limit.
- **Secure updater core (FR-02, FR-03, DEC-03, DEC-05):** fork feed =
  `PhilopaterSh/simplewall` releases; manifest origin pinned; detached
  `manifest.sig` (raw 64-byte r||s over exact manifest.json bytes)
  verified via CNG `BCRYPT_ECDSA_PUBLIC_P256_MAGIC` import on the
  precomputed SHA-256 digest (crypto choice per DEC-02 — CNG only, no
  new third-party dependency); sha256 of the artifact; monotonic version;
  upstream feed dropped. Every failure path logs and aborts (OPS-01,
  SEC-01).
- **Bootstrap tooling (DATA-01, RSK-02, RSK-04):** keygen (BCrypt pair,
  public key exported in the embedded blob format), manifest signer, and
  a self-test (sign→verify round-trip + tampered-vector failure) that
  must pass before the updater is enabled.
- **Compile-time contract (FR-10, DEC-04):** `C_ASSERT` arity/type guards
  on the consumer-dependency API list, stated as the two fork call
  shapes.

## Verification strategy

- Build gate: MSVC green with the vendored routine (NFR-03); no new
  third-party crypto dependency (NFR-02).
- Bootstrap self-test vectors gate RSK-04 (QA3).
- Manual: MITM simulation (self-signed proxy) aborts; tampered artifact
  dropped; junction in cache dir not followed; rollbacked manifest
  rejected; healthy flow completes the existing UX (NFR-01).
- Round-1 regression check: the fail-safe rules posture (compiled-in
  floor, no on-disk override) is untouched (RSK-05).

## Risks carried forward

- RSK-01: accepted — upstream auto-tracking stops; manual merges.
- RSK-02: accepted — key loss blocks updates until rotation; key-epoch
  field and runbook documented.
- RSK-03: accepted — upstream routine fixes merge manually; the audit is
  the patch baseline.
- RSK-04: gate — CNG normalization proven by test vectors before enable.
- RSK-05: accepted — rules/language unification deferred to Round 3;
  Round-1 posture stays shipped behavior.
