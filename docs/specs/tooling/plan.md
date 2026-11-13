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

## C unification approach (r3 — DEC-08/09/10)

Two research agents mapped the reuse surface; every C tool REUSES the
vendored library instead of reimplementing (owner directive: build on
what exists, in the program's language):

- Vendor change first (T008, 2 lines): `_r_update_verifysignature`
  loses `static` in vendor/routine/rapp.c and gains its declaration in
  vendor/routine/rapp.h — preflight then calls the PRODUCTION verifier
  (DEC-09) via `_r_update_setpublickey (UPDATE_PUBLIC_KEY,
  RTL_NUMBER_OF (UPDATE_PUBLIC_KEY))` (the exact src/main.c:1840 call
  shape) against the repo feed pair read with `_r_fs_readbytes`.
- `tools/preflight.vcxproj` + `tools/preflight.c` (T009): console
  bootstrap `_r_app_initialize(NULL)` under APP_CONSOLE; checks via
  routine APIs — `_r_res_queryversionstring(path)` (d), imports walk
  (native, ~60 lines), DllCharacteristics read (native), RCDATA via
  `_r_sys_loadlibrary(LOAD_LIBRARY_AS_IMAGE_RESOURCE | AS_DATA_FILE)` →
  `_r_res_loadresource` → `_r_sys_decompressbuffer` (LZNT1→XPRESS
  order) → `_r_xml_*` count (e), embedded-key scan (b1), Authenticode
  via the src/helper.c:703-956 CryptCATAdmin+WinVerifyTrust pattern
  (a), feed verification via the production verifier (b-feed, DEC-09);
  ground truth = the same tools/preflight-ground-truth/*.json data
  files (single source of parity constants, format UNCHANGED per
  DEC-11 — read by a minimal-JSON-subset reader: flat keys, string
  arrays, one integer, fail-closed outside the subset per SEC-02,
  provenance fields equality-checked); `--ci` profile parity with
  python (incl. AS5 SKIP labels and --json machine output).
  VENDOR-LANE NOTE (RSK-05): T008 is a minimal 2-line export diff,
  sequenced against the vendor-lane session state at build time —
  the tools lane never refactors vendor code; tools adapt to vendor.
- `tools/dnsrig.vcxproj` + `tools/dnsrig.c` (T010): raw winsock2 UDP/53
  (no socket code exists in routine — confirmed gap), minimal wire
  format, NXDOMAIN default, OPT tolerance, TCP unbound, per-query
  `_r_console_writestringformat` logs, `-selftest` loopback mode;
  ini via GetPrivateProfileString (house style, rapp.c:1954).
- `tools/feedserver.vcxproj` + `tools/feedserver.c` (T011): schannel
  server (secur32+schannel+crypt32, SECURITY_WIN32 defined before
  sspi headers — no in-tree precedent, agent-confirmed gap), minimal
  HTTP/1.1 GET, no listing, fail-closed on missing feed pair.
- Build (all tools, DEC-10): per-tool vcxproj — SubSystem=Console,
  APP_CONSOLE define, wmain, CharacterSet=Unicode, IncludePath +
  vendor\routine\, OutDir=$(SolutionDir)bin\$(PlatformArchitecture)\,
  GenerateManifest=false, /DEPENDENTLOADFLAG:0x800 /BREPRO, NO
  CppWinRT/NuGet imports (src\uwp.cpp is the only winrt consumer —
  agents confirmed tools never compile it); pragmas for the extra
  libs in each tool's own .c (house style: main.h:13-22 precedent).
- CI (T012): one additional msbuild invocation per tool vcxproj
  (v143 override, same style as smoke-test.yml:30) replacing the
  python preflight/self-test steps once the C tools pass; artifacts
  gain the tool exes' hashes.
- Verification (T013): AS1-AS9 re-executed through the C tools
  (NFR-03), then the python versions are retired (DEC-08).
