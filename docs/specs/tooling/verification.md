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

## Pending (owner-side, RSK-02)

- Sandbox positive control: rig + feedserver + trusted root -> the
  app's own updater verifies the signed feed; tampered variant rejected
  (AS8/AS9). Windows Sandbox absent on the owner machine.
- C dnsrig/feedserver (T010/T011) verification + T012/T013 CI switch +
  python retirement — in flight at the time of this record.
