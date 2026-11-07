# Specification: Tooling Round — Own Release Preflight + Feed DNS Rig

Derived from design.md r2 (owner scope approval recorded there; fresh-context
goldfish review integrated). Preserve scope, identifiers, acceptance criteria,
decisions, and unresolved gates; do not re-interpret settled choices.

## User stories

- US1: As the release engineer I run one preflight command against the built
  exe so that a signed release is only possible when all parity checks pass
  (FR-01, FR-02).
- US2: As the CI pipeline I run the `--ci` preflight profile post-build so that
  regressions in imports, version, embedded key, blocklist container, or PE
  flags fail the run without needing any private material (FR-05, DEC-07).
- US3: As a tester I run the DNS rig and feed server inside a disposable VM so
  that the app's own updater verifies the signed feed offline — and tampered
  variants are rejected (FR-03, FR-06).
- US4: As a maintainer I receive a pointed failure message when a parity
  constant drifts after an upstream merge so I can update the cited data file
  deliberately instead of blindly (RSK-01).
- US5: As the developer I use the SAME tools in the program's own language
  (C, via the vendored routine library) so tooling and product share one
  language, one build tree, and the production verifier itself (FR-07,
  FR-08, FR-09, DEC-08, DEC-09, DEC-10).

## Acceptance scenarios

- AS1: Given the signed release exe and reachable ground truth, when preflight
  runs in full profile, then every check prints PASS/FAIL with one-line
  evidence and exit code is 0 only if all selected checks pass (FR-01).
- AS2: Given `src/update_key.h` bytes differ from the exe-embedded key, when
  check (b1) runs (even in `--ci`), then preflight FAILs citing the byte offset
  of the first divergence (FR-01, SEC-02).
- AS3: Given the owner machine where the key JSON exists, when full-profile
  check (b2) runs, then the JSON's pinned SHA256 is verified before its content
  is compared, and any mismatch FAILs (DEC-03, RSK-04).
- AS4: Given ground-truth data files are missing or unparseable, when preflight
  starts, then it FAILs with the explicit file and reason — never a silent skip
  (FR-02, SEC-02).
- AS5: Given a CI runner that built an unsigned exe, when `--ci` preflight
  runs, then checks (a)/(b2) are labeled `SKIP (release profile)` and all other
  checks still gate the run (FR-05, DEC-05).
- AS6: Given the DNS rig config maps `raw.githubusercontent.com=127.0.0.1`,
  when a client queries that name (OPT record present), then the rig answers
  the mapped A record and logs the query; when any other name is queried, the
  rig answers NXDOMAIN (FR-03).
- AS7: Given the rig's self-test mode, when run on CI, then it self-queries
  over loopback and asserts the mapped answer + NXDOMAIN policy without any
  sandbox or admin rights (FR-04, RSK-02).
- AS8: Given the feed server running with a guest-trusted cert and a feed root
  containing VERSION/VERSION.sig, when the app's updater resolves the feed host
  via the rig and requests over TLS, then the server serves exactly those files
  and logs the requests (FR-06).
- AS9: Given a tampered VERSION.sig in the feed root, when the updater's
  verification runs against the rig+server harness, then the update fails
  closed and no artifact lands (harness-level witness of the app's own
  fail-closed path).
- AS10: Given the C preflight (tools/preflight.vcxproj → bin\64\preflight.exe),
  when run in full profile on the signed release exe, then it prints the same
  six-check verdict table as the python implementation and exits 0 (FR-07,
  NFR-03).
- AS11: Given the repo feed pair (VERSION + VERSION.sig), when the C preflight
  runs its feed-verification check, then it calls the UN-MODIFIED production
  verifier with unchanged logic (static-export change only, DEC-09) via
  `_r_update_setpublickey` with the embedded key, then it passes on the true
  pair and fails on a tampered pair
  (FR-07, DEC-09).
- AS12: Given the C dnsrig (bin\64\dnsrig.exe), when run with `-selftest`, then
  it passes the same loopback assertions (mapped answer, NXDOMAIN default,
  OPT tolerance) without a sandbox (FR-08, NFR-03).
- AS13: Given the C feedserver (bin\64\feedserver.exe) started with a
  guest-trusted cert and the feed root, when the updater requests over TLS,
  then it serves the manifest pair and logs requests, and refuses to start
  without the feed pair (FR-09, NFR-03).

## Success criteria

1. Full-profile preflight on the current signed exe (03c4c0d4…) passes all
   selected checks locally (release engineer machine).
2. `--ci` preflight passes on CI for the same tree (unsigned build tolerated
   via profile split).
3. Rig self-test passes in CI without admin/sandbox.
4. All parity data files carry provenance headers (source binary version +
   SHA256) and are referenced by preflight, never hardcoded in code.
5. `goldfish check design.md spec.md plan.md tasks.md` exits 0.
6. No file in the chain or tools adds a python package dependency
   (SEC-01) or private material to the repo (DEC-07).
7. Every tool file carries an attribution header citing its concept sources
   (MIT-only borrows); no GPL third-party code anywhere (NFR-01, DEC-06).
8. Preflight on the 1 MB exe completes in < 5 s deterministically; the DNS
   rig binds and answers in < 1 s (NFR-02).
9. The C tools build from per-tool vcxproj files in CI WITHOUT the NuGet
   restore step (no CppWinRT coupling — DEC-10) and land in bin\64\.
10. The C tools re-pass AS1-AS9 through the C binaries (including AS5 --ci
    SKIP labels and AS7 self-test) AND pass AS10-AS13 (production-verifier
    feed positive/tamper included) — only then are the python versions
    retired (DEC-08, NFR-03).
