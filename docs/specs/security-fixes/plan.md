# Implementation Plan: Security Fixes (r2)

Derived from spec.md; preserves the approved decisions (design r2).

## Approach

- FIX-1 (vendor/routine/rapp.c, single function _r_update_install): open cache_path GENERIC_READ share(READ|DELETE) -> reparse check (FileAttributeTagInformation) -> sha256 via _r_crypt_getfilehash on the held handle (REQUIRED for the installer component, DEC-02) -> mismatch/missing: delete artifact + refuse -> _r_sys_runasadmin while held -> close. Reuse the download-path verify idiom (rapp.c:2160-2293). Hold spans the blocking ShellExecuteEx call (DEC-01, review-corrected).
- FIX-2 (src/composite_integrity.c): delete the GetSecurityDescriptorDacl round-trip; pass the SetEntriesInAclW result directly as pDacl; three-ACE policy (Administrators FULL, SYSTEM FULL, process-token user READ); PROTECTED_DACL_SECURITY_INFORMATION; fix the main.c:1885 dead comment during implementation; document the declined-UAC debug-log exception (RSK-02).
- FIX-3 (src/notifications.c): gate the IDM_OPENRULESEDITOR branch on _r_ctrl_isenabled(hwnd, IDC_ALLOW_BTN) (FR-07 proxy precedent, notifications.c:1664) + rate-limited refusal log; mirror the sibling-branch shape exactly (DEC-04).
- FIX-4 (src/update_key.h): comment corrected to BIG-endian verbatim + bench reference (DEC-05).
- BACKLOG routing: append the six audit minors to docs/BACKLOG.md with the evidence location (design r2 deliverable).

## Verification strategy

- Build Release x64 v143 (app) - zero errors.
- FIX-1: CI launch test exercises the full updater path shape; the hash-verify reuses the bench-proven CNG conventions; manual NSIS round owed in the sandbox (RSK-01) before re-release.
- FIX-2: runtime verification rides the owner interactive round (AS5 reads the DACL via icacls); compile-level correctness asserted by the reviewer-confirmed shape.
- FIX-3: code review parity vs the sibling branches (AS6 behavior identical to ALLOW/BLOCK gate).
- Gates: goldfish check (this chain) exit 0 + check-chain-artifacts 0 violations before and after the implementation commit.
- CI dispatch-then-merge on feat/security-fixes (ledger row 34 protocol).

## Approach (r3 addition: FIX-5)

- FIX-5 (DEC-07): sweep every `_r_fs_setpos` caller in vendor/routine/rapp.c
  (2214/2240 download-verify + 3207/3231 install-verify) to pass a zeroed
  LARGE_INTEGER by pointer, matching the vendored PLARGE_INTEGER contract
  (the log.c:146 + rapp.c:3305 idiom). `_r_fs_setsize` callers verified clean.
  Re-release v3.9.4 follows immediately (RSK-06).

## Risks carried forward

- DEC-03 (FR-12 DACL policy) reflected: FIX-2 implements Administrators FULL + SYSTEM FULL + process-token user READ, PROTECTED, non-fatal (Approach FIX-2).
- DEC-06 (scope fence) reflected: no gui/, no feed-format, no composite-beyond-integrity changes; the parallel session's src/gui/ lane is untouched.
- RSK-04 (vendor-lane stale state) acknowledged: FIX-1 measured against the current vendor state (999a9294); single-function diff only.
- RSK-05 (vendor-lane coordination) acknowledged: minimal diff, sequenced with the vendor lane; no vendor refactoring.

- RSK-05 (vendor-lane coordination): acknowledged - FIX-1 is a single-function minimal diff in vendor/routine/rapp.c, measured against the current vendor state (last vendor commit 999a9294, owner lane); no vendor refactoring.

- RSK-01 (installer self-access) / RSK-02 (non-elevated writes; declined-UAC debug-log exception) / RSK-03 (parity refusal) - carried from design r2 with their gates.


## r3 risks

- RSK-06: v3.9.3 live with the setpos crash on language-verify/install paths
  — v3.9.4 re-release owed immediately; the raw feed pair stays
  consistent-stale meanwhile (fail-safe).
- DEC-07 acknowledged: the setpos sweep becomes the standing ABI-check for
  every future vendor call site (mechanical grep, not trust).
