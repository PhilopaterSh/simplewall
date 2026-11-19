# Verification: Tooling Round (r1-r3)

> Evidence record. Gate runs are also echoed in commit messages; CI runs
> are queryable on GitHub Actions (branch feat/routine-hardening).

## Mechanical gates

- `goldfish check design.md spec.md plan.md tasks.md` = exit 0 at every
  recorded revision freeze: r2 (0de3f917), r3 (e7f1ce5b), and the T008/
  T009 implementation commit (999a9294). Gate failures were caught and
  fixed in-pass: 6 findings on r1 first pass, 2 on r3 first pass.
- `tools/check-chain-artifacts.py` (added post-audit): FAILed the chain's
  own handoff/verification gaps, which this file + the filled handoff.md
  close (self-attesting run recorded in the same commit as this file).

## Empirical benches and runs

- `tools/cng-signature-bench.py`: 4/4 PASS exit 0 (standing RSK-04 gate;
  established during the r4 reconciliation, re-run before every
  feed/signature change).
- C preflight (T009, bin/64/preflight.exe): verified by the implementer
  agent AND independently re-run by the owner lane: --ci profile 9/9
  green exit 0 on a stable exe copy; tampered-key copy -> (b1) FAIL
  exit 1; production verifier (DEC-09): positive PASS on repo
  VERSION+VERSION.sig, tampered sig rejected (0xC000A000); parity with
  release-preflight.py byte-for-byte in pass AND fail states; timing
  0.5-2.3 s (NFR-02 < 5 s). Fail-closed verified: missing ground truth,
  --app-h missing, sharing-violation on a locked exe.
- python preflight/dnsrig (T007): full profile 8/8 PASS on the signed
  exe (1.25 s); tamper exit 1; dnsrig self-test 3/3 PASS; in-flight
  catch: parallel session's unsigned rebuild detected by check (a).
- CI: run 42326397797 (commit c2c3b3ef) SUCCESS with the required
  preflight --ci step + dnsrig self-test on windows-latest.

## C unification (T010-T013) — verified 2026-11-07

- dnsrig.c/feedserver.c (T010/T011): both build clean (v143 override);
  dnsrig -selftest byte-identical to python (3 PASS, exit 0 — verified
  independently by the owner lane); config smoke wire-verified (0xC00C
  pointer, A/IN, TTL 60, NXDOMAIN default, OPT tolerated); feedserver
  schannel handshake fixed at root cause (zeroed CredHandle never copied
  into conn.cred), PFX-only cert, 200/404/403 + traversal refusal
  verified without admin; fail-closed: missing feed pair, bad mapping
  IP refuses start, 30 s socket timeouts. Documented deviations:
  invalid-IP refuse-to-start (python crashed on first query), 403 vs
  404 for listing, one-request-per-connection.
- T012: CI builds all three tool vcxprojs (v143 override, no NuGet) and
  runs bin/64/preflight.exe --ci --json + bin/64/dnsrig.exe -selftest
  (exit-code based — the routine console writer is invisible to pipes
  by design, documented).
- T013 retirement: AS1-AS9 re-passed through the C binaries (AS5 SKIP
  labels + AS7 self-test included) AND AS10-AS13 (production-verifier
  feed positive/tamper; rig parity; feedserver acceptance) — python
  tools retired per DEC-08 in the same commit as this record.
- Known CI note: SAC intermittently blocks freshly built unsigned exes
  on the OWNER machine (per-hash verdicts; CI runners unaffected).

## Pending (owner-side, RSK-02)

- Sandbox positive control: rig + feedserver + trusted root -> the
  app's own updater verifies the signed feed; tampered variant rejected
  (AS8/AS9). Windows Sandbox absent on the owner machine.
- C dnsrig/feedserver (T010/T011) verification + T012/T013 CI switch +
  python retirement — in flight at the time of this record.
