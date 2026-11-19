# Tasks: Security Fixes (r2)

<!-- Every task references its key parent, or carries [enabling] for
explicitly approved supporting work. The enabling budget defaults to 2. -->

- [x] T001 implements FIX-1: _r_update_install hardening - write-excluding open, reparse check, in-handle sha256 re-verify, hash-required fail-closed (DEC-02), hold through ShellExecuteEx (FR-01, FR-02, DEC-01, DEC-02, SEC-01, SEC-05, RSK-01)
- [x] T002 implements FR-03 + FR-12: FIX-2 composite_integrity.c DACL rewrite - direct PACL, three-ACE policy, PROTECTED flag, process-token user SID, main.c:1885 comment fix (FR-03, FR-12, DEC-03, NFR-01, RSK-02)
- [x] T003 implements FR-04 + FR-07: FIX-3 IDM_OPENRULESEDITOR gate - IDC_ALLOW_BTN proxy control + rate-limited refusal log (FR-04, FR-07, DEC-04, RSK-03)
- [x] T004 implements FR-05: FIX-4 update_key.h endianness comment correction (FR-05, DEC-05, NFR-02)
- [x] T005 routes the audit minors (incl. NFR-02 the /W4+/analyze gate) to docs/BACKLOG.md with the evidence location (DEC-06, NFR-02, design r2 BACKLOG deliverable) [enabling]
- [x] T006 executes verification: build clean, CI dispatch green on feat/security-fixes, gates exit 0, merge per the ledger row 34 protocol (AS1-AS8 evidence) [enabling]
- [x] T007 implements FIX-5 (r3): the _r_fs_setpos ABI sweep — rapp.c 2214/2240/3207/3231 pass a zeroed LARGE_INTEGER by pointer; re-release v3.9.4 (FR-01, FR-03, DEC-07, RSK-06)
