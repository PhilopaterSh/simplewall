# Tasks: Tooling Round — Own Release Preflight + Feed DNS Rig

<!-- Every task references its key parent, or carries [enabling] for
explicitly approved supporting work. The enabling budget defaults to 2. -->

- [ ] T001 implements preflight core: CLI skeleton, PE header/resource walk, checks (c) import parity + (d) version resource + (f) PE flags against ground-truth data files with provenance validation (FR-01, FR-02, RSK-01, SEC-01)
- [ ] T002 implements preflight crypto/container checks: (a) Authenticode via PowerShell ConvertTo-Json (full profile), (b1) embedded-key vs in-tree update_key.h, (b2, owner-side) JSON cross-check with pinned SHA256, (e) SWC1 container integrity (stored-SHA256 + LZNT1→XPRESS decode mirroring src/db.c + blocklist parity), `--ci` profile SKIP labels, `--json` output (FR-01, DEC-05, DEC-07, RSK-04)
- [ ] T003 implements tools/dnsrig.py: UDP/53 wire-format stub, per-host overrides, NXDOMAIN default, OPT tolerance, TCP refusal, per-query logging, `--self-test` loopback mode (FR-03, FR-04, DEC-04, RSK-02)
- [ ] T004 implements tools/feedserver.py: stdlib TLS static server for the feed root, caller cert/key, no listing, request log (FR-06, DEC-01)
- [ ] T005 creates tools/preflight-ground-truth/ data files with provenance headers: imports.json, blocklist.json, pe-flags.json, key-json-sha256.txt (DEC-03, RSK-01, RSK-04) [enabling]
- [ ] T006 wires CI: trigger extension, required `--ci` preflight step, optional dnsrig self-test step, preflight.json artifact upload (FR-05, DEC-05) [enabling]
- [ ] T007 executes the verification strategy: full-profile PASS on signed exe, tamper/missing-input fail-closed tests, `--ci` + self-test green, NFR-02 timing, SEC-01 stdlib audit, attribution-header audit across all tool files (NFR-01, NFR-02, SEC-01, SEC-02)
