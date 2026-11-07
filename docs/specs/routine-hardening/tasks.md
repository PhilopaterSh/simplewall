# Tasks: Round 2 — Routine Hardening & Secure Updater

- [x] T001 Vendor `routine/src` into `vendor/routine/`, update `simplewall.vcxproj` IncludePath, and align the two ABI shapes to the fork contract (`_r_sys_setprocessprivilege(hwnd,...)` 5-arg; `_r_fs_createfile(&handle,&path,...)`) (FR-09, DEC-01, DEC-04, NFR-03)
- [x] T002 Patch F1: delete the `SECURITY_FLAG_IGNORE_UNKNOWN_CA` retry in `_r_inet_openurl`; TLS secure failures abort and log (FR-01, SEC-01, OPS-01)
- [x] T003 Patch F4: registry probe-then-read becomes a bounded retry loop on `ResultLength` (the unbounded copy at routine.c:15157) (FR-05)
- [x] T004 Patch F5: reference the config object body while holding its protecting lock; close the find-then-add gap (rapp.c:1346-1366) (FR-06)
- [x] T005 Patch F6: `FILE_OPEN_REPARSE_POINT` + `GetFinalPathNameByHandle` verification on update-path opens + restrictive DACL on the cache dir (FR-07, SEC-02)
- [x] T006 Patch F3: exclusive handle through download+hash+rename; atomic `FileRenameInformation`; re-open by path only after integrity passes (FR-04)
- [x] T007 Patch LOWs: REG_SZ zero-length guard, swapreference order, quoted installer args, INI values bounded with documented limit (FR-08)
- [x] T008 Add `C_ASSERT` arity/type guards for the consumer-dependency API list, stated as the two fork call shapes (FR-10, DEC-04)
- [x] T009 Redesign the updater feed: fork releases origin pinned over HTTPS, manifest fetch fail-closed, upstream feed dropped (FR-02, DEC-03, NFR-01)
- [x] T010 Implement the verification core: CNG ECDSA P-256 import (P256_MAGIC blob), detached raw r||s verify on the precomputed SHA-256 digest, artifact sha256 check, monotonic version (FR-03, DEC-05, NFR-02)
- [x] T011 Build the bootstrap tooling: keygen (public key exported in the embedded blob format), manifest signer, self-test vectors (round-trip + tampered failure) (DATA-01, RSK-04, RSK-02)
- [x] T012 Wire the update flow fail-closed end-to-end with fail-visible logging on every failure path (OPS-01, SEC-01, NFR-01)
- [x] T013 Write `docs/specs/routine-hardening/verification.md`: MITM simulation, tampered artifact, junction test, rollback test, key generation/rotation runbook (RSK-02, RSK-04, RSK-05, DATA-01)
- [x] T014 ABI alignment patch set (DEC-04 full-caller sweep, r3 amendment): 4x `_r_fs_openfile` internal callers to out-first/path-second order; `_r_path_makebackup` def to PR_STRINGREF contract; queryversion order fix (f4bfda30); 2x `_r_log` description/code swap; `_r_crypt_getfilehash`, 2x `_r_str_environmentexpandstring`, 2x `_r_sys_loadlibrary2`, `_r_res_loadresource` caller order; 6x const alignment (FR-01, DEC-04; commits ccd618a9, 02d99172) *(root-caused from the first interactive run's 0xC0000005; warnings C4024/C4028 60+ -> 0)*
- [x] T015 Post-fix verification: two fresh-context goldfish audits — vendor patch set VERDICT patch-set-sound (14 openfile sites, 5 r_log sites, 9-function sweep: zero crash-capable mismatches remain) + full src re-audit (all Round-1 fixes VERIFIED; 1 blocking found and fixed: FR-08 `enum_key` init at 015f95ce; + InterlockedIncrement counter, degraded-reset on intentional disable); cppcheck clean on 9 modified files; build exit 0; exe SHA256 d8078041…911d8 (OPS-01, NFR-02, NFR-06)
