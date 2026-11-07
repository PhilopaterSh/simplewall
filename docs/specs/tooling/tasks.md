# Tasks: Tooling Round — Own Release Preflight + Feed DNS Rig

<!-- Every task references its key parent, or carries [enabling] for
explicitly approved supporting work. The enabling budget defaults to 2. -->

- [x] T001 implements preflight core: CLI skeleton, PE header/resource walk, checks (c) import parity + (d) version resource + (f) PE flags against ground-truth data files with provenance validation (FR-01, FR-02, RSK-01, SEC-01)
- [x] T002 implements preflight crypto/container checks: (a) Authenticode via PowerShell ConvertTo-Json (full profile), (b1) embedded-key vs in-tree update_key.h, (b2, owner-side) JSON cross-check with pinned SHA256, (e) SWC1 container integrity (stored-SHA256 + LZNT1→XPRESS decode mirroring src/db.c + blocklist parity), `--ci` profile SKIP labels, `--json` output (FR-01, DEC-05, DEC-07, RSK-04)
- [x] T003 implements tools/dnsrig.py: UDP/53 wire-format stub, per-host overrides, NXDOMAIN default, OPT tolerance, TCP refusal, per-query logging, `--self-test` loopback mode (FR-03, FR-04, DEC-04, RSK-02)
- [x] T004 implements tools/feedserver.py: stdlib TLS static server for the feed root, caller cert/key, no listing, request log (FR-06, DEC-01)
- [x] T005 creates tools/preflight-ground-truth/ data files with provenance headers: imports.json, blocklist.json, pe-flags.json, key-json-sha256.txt (DEC-03, RSK-01, RSK-04) [enabling]
- [x] T006 wires CI: trigger extension, required `--ci` preflight step, optional dnsrig self-test step, preflight.json artifact upload (FR-05, DEC-05) [enabling]
- [x] T007 executes the verification strategy: full-profile PASS on signed exe, tamper/missing-input fail-closed tests, `--ci` + self-test green, NFR-02 timing, SEC-01 stdlib audit, attribution-header audit across all tool files (NFR-01, NFR-02, SEC-01, SEC-02)
- [x] T008 un-statics the production verifier: remove `static` from `_r_update_verifysignature` in vendor/routine/rapp.c + add the declaration to vendor/routine/rapp.h (DEC-09)
- [x] T009 implements tools/preflight.vcxproj + tools/preflight.c: routine-API checks (resource mapping, decompress, XML count, queryversionstring, production-verifier feed check), native imports/flags/key-scan, CryptCATAdmin+WinVerifyTrust Authenticode, --ci parity, same ground-truth data files (FR-07, DEC-08, DEC-09, DEC-10)
- [x] T010 implements tools/dnsrig.vcxproj + tools/dnsrig.c: raw winsock2 UDP/53 server, NXDOMAIN default, OPT tolerance, TCP unbound, -selftest loopback, GetPrivateProfileString config (FR-08, DEC-10)
- [x] T011 implements tools/feedserver.vcxproj + tools/feedserver.c: schannel TLS static server, caller cert, no listing, fail-closed on missing feed pair (FR-09, DEC-10)
- [x] T012 updates CI: build the three tool vcxproj files, replace python preflight/self-test steps with the C equivalents, extend artifact list (FR-05, DEC-08, DEC-10)
- [x] T013 re-executes AS1-AS9 through the C tools (verdict parity + production-verifier feed positive/tamper), retires the python versions (FR-07, FR-08, FR-09, DEC-08, NFR-03)
