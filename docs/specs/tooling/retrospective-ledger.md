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

| 23 | 2026-11-07 | CI loop + instrumentation (dnsrig) | self-test failure on runner only | 5-iteration causal chain: invisible CI output -> out_write fallback -> uninitialized rcode -> server counters -> SERVER NOTE showed qname garbage -> missing NULL terminator in _rig_parse_qname (one line) | REAL — fixed 18d75273; CI green | runs 42381287177..42387841195 |
| 24 | 2026-11-07 | same loop | dnsrig lookup + tooling | (a) _r_str_compare misused (version comparator for equality -> _wcsicmp); (b) JSON->heredoc->python escaping injected real newline/form-feed into C literals TWICE -> standing rule: patch scripts are FILES, literals composed via chr() | REAL | same runs |
| 25 | 2026-11-10 | lane merge (bypass-class) | AGENTS.md | the composite lane forked BEFORE the 2026-11-07 governance adoption and still carried upstream placeholder content; merge 19f7da7d took the branch side and silently replaced the adopted EGM procedure, mislabeled "junk" — ledger went dark 9 days | CAUGHT-BY: process re-audit (agent, 2026-11-13), not mechanics | process re-audit finding 1 |
| 26 | 2026-11-10 | CI loop (composite lane) | headless suites + bench probes | phase3 r2 NEEDS-REVISION integrated (a5d5c02c); T012 bench probes "live-run green" (dde35f45); gui gate fix rounds e378ab9c/76e404fc | REAL | composite lane commits |
| 27 | 2026-11-10 | external senior review (fresh agent) | the whole composite effort | verdict SOUND-WITH-CONDITIONS; 4 conditions (empirical testing, S4, no machine-wide audit default, signing re-key); triage was pending | MIXED — 2 integrated, 1 partial, 1 pending (security re-audit 2026-11-17 table) | review-external-senior-2026-11-10.md |
| 28 | 2026-11-10 | RSK-01 fail-closed trigger (as documented) | imports.json | WS2_32.dll re-applied exactly per the row-22 trigger, citing T002 commit 926a4aba (InetPtonW); verified 25/25 against committed tree | REAL — the self-documenting ground-truth rule survived the AGENTS.md clobber | da1eac0b |
| 29 | 2026-11-13 | process re-audit + artifact gate extension | repo tree | 2.2MB build artifacts + scratch committed inside gate-attested commits (test_dns.exe, bin/mergetest/*, tests/dbg3.c); no gate read the tree | REAL — check-chain-artifacts extended with governance markers + tree-hygiene scan; artifacts removed | process re-audit finding 2 |
| 30 | 2026-11-17 | security re-audit (fresh agent) | 24.7K-line composite delta | VERDICT BLOCK: orphan reconcile deletes rule+global filters every apply (enforcement loss); S4 incomplete in applyall; resolver invariant holes; DACL locks user out; phase3 inert-in-binary | REAL — triaged to the composite lane; the RELEASED v3.9.2-hardened.1 predates composite code and is untouched | security re-audit report |

## Anti-pattern counts (recomputed 2026-11-17)

- Reviewer/implementer precision: tracking via rows above (6 wrong-or-missed vs 12+ real catches since adoption of instrumentation).
- Gate bypasses / silent clobbers to date: **2** (row 15 owner-caught; row 25 lane-merge clobber — audit-caught).
- Benches deployed before dispute rather than after: **0 / 3** (still reactive; empirical-arbiter-first rule adopted but not yet mechanical).
- Ledger health: dark 2026-11-10..13 (clobber consequence); healed 2026-11-17 by this commit.

| 25 | 2026-11-17 | fresh-context product security audit (owner-commissioned full-scope, agent 1 of 3) | merged product @ e24a6cfc | VERDICT SOUND-WITH-GAPS: all 25+ hardening claims verified real (zero fake fixes); 3 MAJOR: (1) updater install window fail-open (no re-verify at elevated-exec time, rapp.c:3137-3163) (2) composite_integrity.c FR-12 broken (SetEntriesInAclW result misused as SD + missing user ACE + no PROTECTED flag) (3) notifications IDM_OPENRULESEDITOR mints+applies PERMIT ungated (notifications.c:1883-1947) | REAL — pending EGM fix chain | agent report 2026-11-17 |
| 26 | 2026-11-17 | same audit | release v3.9.2-hardened.1 | the released exe carries finding-1 (install-window TOCTOU, same-user scope) — re-release owed after the fix | REAL | same |
| 27 | 2026-11-17 | PR archaeology (owner asked about GUI work) | PR #12 + master | PR #12 was STALE (head 71bc3c3b = master ancestor): its "diff" was master's own governance work REVERSED — merging would have restored committed binaries + clobbered AGENTS.md. Closed instead. AND: the GUI work the owner remembered EXISTS as a full chain on master: docs/specs/gui/ (design + handoff + mockup-r1.html interactive RTL 6-page + coverage matrix FR-15) @ 71bc3c3b | REAL — stale PR closed; GUI chain confirmed on master | merge-base verification |
| 28 | 2026-11-17 | CI-dispatch protocol (no pre-merge CI on composite branches) | PRs #15/#9/#12 | dispatched smoke-test on each PR head BEFORE merge: #15 green→merged, #9 green→merged, #12 red→diagnosed→closed as stale. Workflow-dispatch-then-merge = the new standing merge protocol for untriggered branches | REAL | runs 43981116802/43981128547/43981139479 |

## Standing rule adopted from this ledger (empirical-arbiter-first, roadmap item 1)

> Any BLOCKING finding about observable behavior must attach a reproduction
> (bench, script, or command output) at review time; without one it is
> labeled `hypothesis — non-gating` until arbitrated empirically.
> Precedent: row 6 (a wrong BLOCKING came within one accepted review of
> ratifying a regression).
