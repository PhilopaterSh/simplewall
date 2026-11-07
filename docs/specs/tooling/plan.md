# Implementation Plan: Tooling Round — Own Release Preflight + Feed DNS Rig

Derived from spec.md; preserves the approved decisions (design r2).

## Approach

Pure python-stdlib tools under `tools/`, one module per tool, each with
attribution + provenance headers (DEC-01, DEC-06, NFR-01):

- `tools/release-preflight.py` (T001–T002): argparse CLI (`--ci`,
  `--json`, `--thumbprint`, `--app-h`, `--ground-truth-dir`). Check
  modules in one file, ordered execution, first-failure does not abort
  (full table printed), exit code aggregates. PE parsing reuses the
  in-session stdlib patterns (header/resource-directory walk); SWC1
  decode mirrors `src/db.c` (LZNT1 then XPRESS via ntdll ctypes,
  stored-SHA256 check over the plaintext) — DEC-02. Authenticode via
  PowerShell `Get-AuthenticodeSignature | ConvertTo-Json` subprocess
  (SEC-01 disclosed OS binary). Version check parses `APP_VERSION`
  from `src/app.h` (override `--app-h`; missing = FAIL, FR-02).
  Ground truth loaded exclusively from
  `tools/preflight-ground-truth/*.json` with provenance headers
  validated (RSK-01); off-repo JSON SHA256 pinned in the same
  directory and verified when reachable (RSK-04).
- `tools/dnsrig.py` (T003): socket-only UDP/53 stub — parse minimal
  DNS wire format, tolerate OPT, answer mapped A records, NXDOMAIN
  default (DEC-04: non-recursive, NXDOMAIN-default pollution control;
  hosts-file alternative documented in the rig header), refuse TCP
  with a documented path, per-query stdout log, `--self-test` mode
  (loopback query assert; FR-04).
- `tools/feedserver.py` (T004): `http.server.ThreadingHTTPServer` +
  `ssl.SSLContext` wrapping a caller cert/key; serves the feed root
  with extension-based content types; no listing; request log (FR-06).
- Ground truth data files (T005): `tools/preflight-ground-truth/`
  imports.json (24-DLL parity from the verified 3.8.7 comparison,
  provenance header), blocklist.json (parity count 1496 + provenance),
  pe-flags.json (0xc160 decomposition), key-json-sha256.txt (pinned
  hash of the off-repo JSON; DEC-03, RSK-04).
- CI wiring (T006): smoke-test.yml gains (i) trigger branch addition,
  (ii) required `python tools/release-preflight.py bin/64/simplewall.exe
  --ci --json` step after the lifetime check, (iii) optional dnsrig
  self-test step, (iv) `preflight.json` added to upload-artifact paths
  (FR-05). Profile split per DEC-05: full profile (a, b2) + CNG bench
  stay owner-side release steps; per DEC-07 the CI path never needs —
  and never receives — private key material, PFX, or the private JSON
  (the `--ci` profile is the enforcement mechanism).

## Verification strategy

- T001/T002: run full profile on the current signed exe (must PASS);
  tamper tests — flip one byte in a copy of the exe's embedded key
  region → b1 FAIL; rename ground-truth dir → explicit FAIL naming the
  file (FR-02); `--ci` profile on the same exe → SKIP labels + exit 0.
- T003: `--self-test` passes locally and in CI (AS7); manual query
  with a raw UDP client exercises OPT-tolerance and NXDOMAIN default.
- T004: serve the repo feed root; curl -k fetch of VERSION + sig over
  TLS loopback; then AS8/AS9 app-level run stays owner-side sandbox
  (RSK-02, documented).
- T006: CI run on the tooling branch shows the three steps green and
  the artifact containing preflight.json (AS5, FR-05).
- NFR-02: time preflight on the 1 MB exe (< 5 s).
- SEC-01: `grep` audit — no imports outside stdlib + disclosed
  subprocesses; SEC-02 covered by the tamper/missing-input tests.
- Whole chain: `goldfish check design.md spec.md plan.md tasks.md`
  must exit 0 before and after implementation commits.

## Risks carried forward

- RSK-01: parity drift on upstream merges — carried; gate = cited-diff
  data-file updates; failure output includes the diff command.
- RSK-02: sandbox absent locally — carried; app-level positive control
  remains the owner's sandbox step; self-test covers CI.
- RSK-03: CI python drift — carried; runner python pinned; ≥3.9 APIs.
- RSK-04: ground-truth integrity — carried; change control + pinned
  JSON SHA256; residual risk stated in design (no cryptographic root).
