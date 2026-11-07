# Design: Tooling Round — Own Release Preflight + Feed DNS Rig

> Revision `2026-11-07-r2` — owner scope approval RECORDED: in-session
> interview 2026-11-07, owner picked **"A: preflight + dnsrig"** from
> sourced options (provenance: Sysinternals closed + version drift,
> pestudio license forbids release-gate use, fakedns MIT-dormant).
> Fresh-context goldfish review of r1: **VERDICT APPROVE-WITH-CHANGES**
> (2 BLOCKING, 4 MAJOR, 5 MINOR) — all integrated in this revision:
> CI-profile split for unsigned CI builds (BLOCKING-1), key-check
> split b1/b2 so no private material is needed on CI (BLOCKING-2),
> ground-truth trust anchor RSK-04 (MAJOR-3), RSK-01 generalized to
> ALL parity constants with provenance headers (MAJOR-4), bench-call
> claim dropped — bench stays a separate owner-side gate (MAJOR-5),
> DNS-rig decision matrix + EDNS0/TCP/wiring prerequisites + explicit
> feedserver scope addition (MAJOR-6), wording/honesty/path/spec/CI
> minors integrated. One scope addition made by the review: the feed
> positive-control journey is impossible without a TLS feed server, so
> `tools/feedserver.py` joins as FR-06 (stdlib; owner may veto).
> Sysinternals and pestudio remain external interactive conveniences;
> nothing in the fork's verification or release path depends on
> closed tools.

## Problem and intended outcomes

The fork's release path and update-feed verification depend on either
closed-source third-party tools (pestudio — license restricts to
"private context"; Sysinternals — closed, version drift, no CI
licensing story) or on hand-run ad-hoc python snippets rebuilt twice
in one week and not repeatable. Two gaps:

1. **Release preflight** — prove, from the binary itself: Authenticode
   validity + expected thumbprint (release profile), the embedded feed
   key vs in-tree `update_key.h` (CI-safe) and vs the off-repo JSON
   ground truth (release profile), import-table whitelist parity,
   version-resource correctness, the embedded internal-profile
   container (SWC1 integrity incl. the stored SHA256 of the plaintext,
   LZNT1→XPRESS decode mirroring the app's reader, and the blocklist
   parity count), and the PE security-flag parity set.
2. **Feed DNS rig + TLS feed server** — exercise the app's own updater
   end-to-end offline: DNS override (or hosts redirect) pointing the
   feed host at a local TLS server that serves the caller-supplied
   VERSION / VERSION.sig pair with a guest-trusted root.

Intended observable outcomes:

- One command against `bin/64/simplewall.exe` prints a PASS/FAIL table
  and exits non-zero on any failure; a `--ci` profile runs the
  CI-safe subset (no signature check, no off-repo inputs) so the CI
  gate is satisfiable on a runner.
- The DNS rig + feed server make the sandbox positive-control (the
  app verifying our signed feed) and tamper cases reproducible.
- Every tool file carries attribution; borrowed logic is MIT-only.

## In scope and out of scope

In scope (this chain):

- `tools/release-preflight.py` — stdlib-only ordered preflight gate
  with `--ci` profile and `--json` output.
- `tools/dnsrig.py` — stdlib UDP/53 DNS stub: per-host A-record
  overrides, NXDOMAIN default, no upstream recursion, per-query
  logging, loopback self-test mode, EDNS0-OPT-tolerant, TCP
  deliberately refused (documented fail-closed).
- `tools/feedserver.py` — stdlib HTTPS server (`http.server` + `ssl`)
  serving a directory as the feed root (VERSION, VERSION.sig, and any
  artifact URLs the manifest names) using a caller-provided
  cert/key pair; cert generation documented via PowerShell
  `New-SelfSignedCertificate` (cert generation is NOT reimplemented
  in python).
- Ground-truth data files under `tools/preflight-ground-truth/` with
  provenance headers (source binary version + SHA256): import parity
  list, blocklist parity count, PE flag parity set.
- CI wiring: preflight `--ci` step + dnsrig self-test step + json
  artifact upload in the existing smoke-test workflow (plus workflow
  trigger extension so the tooling branch exercises them).
- Chain docs under `docs/specs/tooling/`.

Out of scope (prohibited adjacent work):

- sw-trace / ETW tracer (composite Phase-1 EvtSubscribe 5157 pipeline
  covers the network half; file/registry tracing = separate future
  chain).
- Any driver, kernel component, or modification of `src/` or
  `vendor/`.
- Reimplementing the CNG signature bench: the bench stays a separate
  owner-side gate (its inputs — off-repo key JSON + repo feed files —
  do not exist on CI by design); preflight does NOT call it (r2
  review MAJOR-5); attribution lineage only.
- Cert generation inside python; Windows Sandbox orchestration;
  signing, manifesting, or repointing VERSION (owner decisions).

## User journeys and behavior

Preflight (release engineer — full profile):

1. `python tools/release-preflight.py bin/64/simplewall.exe` → ordered
   checks, each prints `PASS/FAIL: <name>` + one-line evidence; exit 0
   only if ALL pass. `--json` emits a machine-readable object.
2. Checks (release profile): (a) Authenticode Valid + thumbprint ==
   configured thumbprint (default `DC91477AF1415F6D7C3B181B1EB2EC45FF907ED0`,
   `--thumbprint` override; verified via PowerShell
   `Get-AuthenticodeSignature` piped through `ConvertTo-Json` —
   OS-provided binary, not a python package); (b1) embedded
   `UPDATE_PUBLIC_KEY` bytes == in-tree `src/update_key.h` bytes;
   (b2, owner-side only) in-tree `update_key.h` == off-repo JSON
   ground truth, with the JSON's pinned SHA256 checked when reachable;
   (c) import-table DLL set == parity list data file (exact set
   match); (d) version resource ProductVersion == `APP_VERSION`
   parsed from `src/app.h` (`--app-h` override; path resolved
   `tools/../src/app.h`; missing = FAIL); (e) RCDATA id=1 is a
   well-formed SWC1 container: `SWC` fourcc + flag byte, stored
   SHA256 == SHA256 of the decompressed plaintext, decode tries
   LZNT1 then XPRESS (mirrors `src/db.c` reader), XML parses, and
   the `rules_blocklist` item count == parity data file; (f) PE
   DllCharacteristics == parity flag set.
3. CI profile (`--ci`): runs (b1) (c) (d) (e) (f) — checks (a) and
   (b2) are release-engineer-authoritative (runner builds are
   unsigned; the off-repo JSON never leaves the owner machine). The
   CI table labels skipped checks `SKIP (release profile)` — visible,
   not silent.

DNS rig + feed server (tester, inside Windows Sandbox):

1. Decision matrix (why the rig exists at all): a hosts-file edit is
   SIMPLER for a pure positive redirect and always wins (Windows
   resolver consults hosts before DNS); the rig's added value is
   (i) NXDOMAIN-by-default for every OTHER name (fail-closed
   pollution control hosts cannot express), (ii) per-query transcript
   logging, (iii) resolver-level control for future phases. The
   harness may use hosts-only for the simplest case; the rig is the
   default when pollution control matters.
2. Wiring prerequisites (documented in the rig header): the guest
   adapter's DNS must point at the rig (or hosts edit must be
   applied), AND the feed server's root certificate must be installed
   into the guest trust store — otherwise WinHTTP fails closed at
   TLS (which is itself a valid fail-closed assertion).
3. `python tools/dnsrig.py --config dnsrig.ini` — UDP/53 only; OPT
   (EDNS0) records tolerated/ignored; TCP queries get a formatted
   refusal (resolver TC-retry then fails closed — documented);
   unknown names → NXDOMAIN (default policy); log line per query.
4. `python tools/feedserver.py --root <dir> --cert <pem> --key <pem>
   [--port 443]` — serves the manifest pair + artifacts over TLS;
   no directory listing; content-type by extension; logs requests.

CI journey: preflight `--ci` runs post-build as a REQUIRED step
(after the app-lifetime check; `preflight.json` joins the artifact
upload list); dnsrig self-test runs as a cheap optional step; a
failed preflight fails the run. Workflow triggers extended so the
tooling branch itself exercises the new steps.

## Constraints and quality attributes

- **SEC-01 (honest boundary)**: zero python PACKAGE dependencies —
  stdlib only; OS-provided binaries (PowerShell) permitted and
  disclosed. No network access in preflight; rig/feedserver bind
  localhost/explicit addresses only.
- **SEC-02**: fail-closed for every missing/unparseable input
  (ground truth, app.h, PE structure, cert files); unknown PE
  structure = FAIL, never best-effort.
- **NFR-01**: attribution headers in every file; MIT-only borrowed
  concepts (Crypt0s/FakeDns, hupe1980/fakedns cited); no GPL
  third-party code.
- **NFR-02**: preflight deterministic, < 5 s on a 1 MB exe; rig
  starts < 1 s.
- **Trust anchor honesty (r2 review)**: preflight is an integrity
  chain anchored on owner-machine state + in-repo change-controlled
  data files — it is not a cryptographic root; residual risk
  recorded in RSK-04.

## Approved decisions

- DEC-01: stdlib-only python tooling; C product untouched; OS
  binaries permitted and disclosed.
- DEC-02: checks map 1:1 to evidence accumulated in prior verified
  rounds; no new check without a provenance story.
- DEC-03: ground truth lives off-repo where private (key JSON); in-repo
  ground truth = change-controlled data files with provenance
  headers; in-tree key material is never trusted without the off-repo
  cross-check (owner-side).
- DEC-04: DNS rig = NXDOMAIN-default non-recursive stub; hosts-file
  redirect documented as the simpler alternative with the decision
  matrix above.
- DEC-05: CI = required `--ci` preflight step + optional dnsrig
  self-test; full profile (a, b2) + CNG bench = owner-side release
  steps; feedserver = manual sandbox tool.
- DEC-06: attribution headers; MIT-only borrows; zero GPL third-party
  code.
- DEC-07: NO private key material, PFX, or private JSON on GitHub —
  the CI/profile split exists precisely so this holds (review
  BLOCKING-1/2 resolution).

## Risks and open questions

- RSK-01 (generalized): ALL hardcoded parity constants drift on
  legitimate upstream merges — imports list, blocklist count, PE flag
  set. Owner: tooling lane. Gate: parity data files updated ONLY with
  a commit message citing the diff that changed the underlying binary;
  CI failure output points the maintainer at the exact diff command.
- RSK-02: Windows Sandbox absent on this machine — app-level
  positive control stays owner-side. Gate: rig self-test mode is
  CI-verifiable without a sandbox (self-query assert).
- RSK-03: CI python version drift. Gate: pin runner python; ≥3.9
  stdlib APIs only.
- RSK-04 (new, from review): ground-truth integrity itself — a
  silently edited parity file or key JSON passes a bad exe. Owner:
  owner. Gate: change control (cited-diff commits) on
  `tools/preflight-ground-truth/`; pinned SHA256 of the off-repo key
  JSON verified by preflight whenever the JSON is reachable;
  explicit residual-risk statement — preflight anchors on owner
  machine state, not on a cryptographic root.
- Open question (owner, non-blocking): preflight also warns
  (WARNING, not FAIL) when the Authenticode NotAfter is < 30 days
  away — cert renewal flow is an owner decision.

## Traceability Key

| Key | Meaning |
| --- | --- |
| FR-01 | Ordered preflight checks (a, b1, b2*, c, d, e, f) with PASS/FAIL evidence lines; exit 0 only when all selected checks pass (*b2 owner-side) |
| FR-02 | Fail-closed on missing/unparseable inputs (ground truth, app.h, PE structures, cert files) |
| FR-03 | DNS rig: UDP/53 A-record overrides, NXDOMAIN default, no recursion, per-query logging, EDNS0-OPT tolerated, TCP refused-documented |
| FR-04 | DNS rig loopback self-test mode (self-query assert) runnable in CI without a sandbox |
| FR-05 | CI: required `--ci` preflight step post-build + json artifact upload; workflow triggers extended to exercise it on this branch |
| FR-06 | `tools/feedserver.py`: stdlib TLS static server for the feed root (manifest + artifacts), caller-provided cert, no listing |
| NFR-01 | Attribution headers; MIT-only borrowed concepts cited; no GPL third-party code |
| NFR-02 | Preflight deterministic < 5 s on 1 MB exe; rig starts < 1 s |
| SEC-01 | Zero python package dependencies (stdlib + disclosed OS binaries) |
| SEC-02 | Fail-closed semantics for every missing/unparseable input |
| DEC-01 | Stdlib-only python tooling; C product untouched |
| DEC-02 | Checks map 1:1 to prior verified evidence |
| DEC-03 | Private ground truth off-repo; in-repo ground truth = change-controlled data files with provenance headers |
| DEC-04 | Rig = NXDOMAIN-default non-recursive stub; hosts-file alternative documented |
| DEC-05 | CI = required `--ci` profile + optional rig self-test; full profile + bench = owner-side |
| DEC-06 | Attribution; MIT-only borrows; zero GPL third-party code |
| DEC-07 | No private key material/PFX/private JSON on GitHub — CI profile split enforces it |
| RSK-01 | ALL parity constants drift on upstream merges — owner: tooling lane; gate: cited-diff updates of parity data files |
| RSK-02 | Sandbox absent locally — app-level positive control owner-side; gate: rig self-test CI-verifiable |
| RSK-03 | CI python drift — gate: pinned runner python, ≥3.9 stdlib only |
| RSK-04 | Ground-truth integrity (silent edit passes bad exe) — owner: owner; gate: cited-diff change control + pinned JSON SHA256 when reachable + residual-risk statement |
