# Retrospective Ledger — findings as data (tooling chain, roadmap item 3)

> Purpose (process audit 2026-11-07): convert workflow effectiveness from
> archaeology to a queryable record. One row per gate/review/bench catch.
> Status column: REAL (finding was correct and acted on) / WRONG (finding
> refuted — arbitration recorded) / CAUGHT-BY (what mechanism caught it).
> Append-only; rows cite their evidence. Session-unverifiable quantities
> (e.g. token counts) are recorded as `[unlogged]` — logging them is
> itself a roadmap item.

## Mechanism catch record (as of 2026-11-07)

| # | Date | Mechanism | Subject | Finding | Status | Evidence |
|---|------|-----------|---------|---------|--------|----------|
| 1 | 2026-11-06 | goldfish review (fresh) | hardening-round-1 diff | wufix `image_path` use-after-free (BLOCKING) | REAL — fixed in `da882347` | routine-hardening design r3 header |
| 2 | 2026-11-06 | goldfish review ×2 (T015) | full src re-audit | FR-08 `enum_key` uninitialized — legit notifications dropped | REAL — fixed in `015f95ce` | routine-hardening design r3 header |
| 3 | 2026-11-07 | goldfish review (26a69775 recon) | feed byte-mode patch | zero-byte-200 NULL deref in bytes shrink-to-fit | REAL — fail-closed rewrite in `fe5df99c` | routine-hardening design r4 follow-up |
| 4 | 2026-11-07 | goldfish review (26a69775 recon) | feed byte-mode patch | ~32KB stringbuilder leak per bytes-mode download | REAL — string-mode-only init in `fe5df99c` | same |
| 5 | 2026-11-07 | goldfish review (26a69775 recon) | feed byte-mode patch | unbounded Content-Length preallocation | REAL — clamped 1MB in `fe5df99c` | same |
| 6 | 2026-11-07 | goldfish review (26a69775 recon) | feed byte-mode patch | BLOCKING: "CNG wants little-endian signature halves" | **WRONG — refuted by cng-signature-bench.py** (BE import 0x0 / LE 0xC000000D; BE verify 0x0 / LE 0xC000A000); the r4 "endianness fix" built on this claim was itself a regression and was reverted | bench = standing RSK-04 gate |
| 7 | 2026-11-07 | empirical bench (cng-signature-bench) | endianness dispute | settled BE-for-blob-and-signature mechanically in seconds | REAL — 4/4 gates exit 0 | tools/cng-signature-bench.py |
| 8 | 2026-11-07 | release-preflight check (a) | parallel session's rebuild | unsigned exe overwrote the signed build — caught in-flight | REAL — re-signed immediately | tooling commit `c2c3b3ef` message |
| 9 | 2026-11-07 | self-verification (T007) | dnsrig.py | inverted QR-bit check — no query ever answered | REAL — fixed pre-ship | tooling commit `c2c3b3ef` message |
| 10 | 2026-11-07 | goldfish review (tooling r1) | tooling design | CI exe unsigned → Authenticode gate would fail 100% in CI; off-repo key JSON absent on CI | REAL — `--ci` profile split + b1/b2 key-check split (DEC-07) | tooling design r2 header |
| 11 | 2026-11-07 | goldfish review (tooling r3) | tooling design r3 | out-of-scope text contradicted DEC-09 (would let a future reviewer reject T008) | REAL — carved exception | tooling design r3 review |
| 12 | 2026-11-07 | mechanical gate (goldfish check) | tooling chain r1/r3 | 6 then 2 traceability-coverage failures (DEC/FR/NFR keys unreflected) | REAL — fixed each pass | gate outputs in session |
| 13 | 2026-11-06 | goldfish review (composite r1) | composite design | factually wrong registry path (missing `Microsoft` segment) + 7 more | REAL — fixed by r3 | composite review-r1..r3 |
| 14 | 2026-11-06 | goldfish review (composite r4) | composite design r4 fixes | 3 of 6 blockings = regressions of r4's own partial fixes | REAL — fixed in r5 | composite review-r4 |
| 15 | 2026-11-06 | owner question | PR #3 (26a69775) | **gate bypass itself** — implementation shipped with zero chain amendments; nothing mechanical caught it | CAUGHT-BY: owner's compliance question, not the process | routine-hardening r4 header |

## Anti-pattern counts (structural, per process audit 2026-11-07)

- Reviewer BLOCKING precision on audited diffs: **3 real / 1 wrong** (75% on blocking+majors; 86% incl. minors — cross-examined 2026-11-07: the refuted BLOCKING is explicit in design.md:53-59, count derived from the design summary since the review text itself is not a committed artifact).
- Gate bypasses to date: **1** (row 15) — caught by owner, not mechanics.
- Benches deployed before dispute rather than after: **0 / 2** (both reactive).
- Ledger completeness: this file is the seed; reviews before 2026-11-07 are captured above; per-run token counts `[unlogged]`.

| 16 | 2026-11-07 | adversarial cross-examination (2nd agent) | the process audit itself | audit provenance correction: AGENTS.md lyrics are UPSTREAM-inherited (henrypp, 8f625967), not fork pollution; PR #9 vanished + "#" unexpanded var = silent automation failure; tooling chain has NO verification.md at all | REAL — 7 claims VERIFIED / 2 PARTIAL / 0 REFUTED; 3 audit blind-spots identified | cross-exam report, session 2026-11-07 |

| 17 | 2026-11-07 | C preflight DEC-11 strict reader | imports.json provenance note | 334-char note with — escapes exceeded the reader subset — fail-closed as designed | REAL — note shortened to ASCII 162; lesson: ground-truth notes stay ASCII + short | session T009 verification |
| 18 | 2026-11-07 | C preflight fail-closed | locked exe (0xC0000043 sharing violation) | parallel session held the binary mid-build — tool refused instead of reading a torn file | REAL — transient; stable-copy retry passed 9/9 | session T009 verification |

| 19 | 2026-11-07 | check-chain-artifacts.py (roadmap item 1, "best buy") | all 4 chains | tooling handoff.md was an unfilled template + tooling/composite had NO verification.md — exactly as the cross-exam predicted | REAL — all three artifacts written the same commit; gate now 4/4 PASS exit 0 | first run of the checker |
| 20 | 2026-11-07 | AGENTS.md rewrite (cross-exam blind-spot #3) | the workflow documentation itself | CLAUDE/GROK pointed agents at upstream song lyrics — every agent's canonical instructions were junk | REAL — replaced with the actual EGM procedure + standing rules; pointer files now resolve to real instructions | commit of record |

| 21 | 2026-11-07 | CI chain-gates step (first live run) | its own install source | pip from the PRIVATE goldfish-gate repo failed on the runner (prompt-script error) — visible failure, not silent | REAL — vendor-pinned 0.2.0 @ 5e31480 (tools/vendor/goldfish-gate-pin + PIN.md provenance); upgrade = owner action with full gate re-run | CI run 42373818607 |

| 22 | 2026-11-07 | CI preflight (c) — change control in reverse | imports.json | the 25-DLL update measured an UNCOMMITTED parallel-checkout build; the committed tree on every branch builds 24 (verified by a clean CI-style build) — CI rejected the constant and protected the committed-tree truth | REAL — reverted to 24 with provenance; re-apply when the udpstats work lands committed (gate EXTRA = the trigger) | CI run 42374193195 + clean rebuild |

## Standing rule adopted from this ledger (empirical-arbiter-first, roadmap item 1)

> Any BLOCKING finding about observable behavior must attach a reproduction
> (bench, script, or command output) at review time; without one it is
> labeled `hypothesis — non-gating` until arbitrated empirically.
> Precedent: row 6 (a wrong BLOCKING came within one accepted review of
> ratifying a regression).
