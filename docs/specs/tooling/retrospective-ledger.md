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

| 16 | 2026-11-07 | adversarial cross-examination (2nd agent) | the process audit itself | audit provenance correction: AGENTS.md lyrics are UPSTREAM-inherited (henrypp, 8f625967), not fork pollution; PR #9 vanished + "#" unexpanded var = silent automation failure; tooling chain has NO verification.md at all | REAL — 7 claims VERIFIED / 2 PARTIAL / 0 REFUTED; 3 audit blind-spots identified | cross-exam report, session 2026-11-07 |
| 17 | 2026-11-07 | C preflight DEC-11 strict reader | imports.json provenance note | 334-char note with — escapes exceeded the reader subset — fail-closed as designed | REAL — note shortened to ASCII 162; lesson: ground-truth notes stay ASCII + short | session T009 verification |
| 18 | 2026-11-07 | C preflight fail-closed | locked exe (0xC0000043 sharing violation) | parallel session held the binary mid-build — tool refused instead of reading a torn file | REAL — transient; stable-copy retry passed 9/9 | session T009 verification |
| 19 | 2026-11-07 | check-chain-artifacts.py (roadmap item 1, "best buy") | all 4 chains | tooling handoff.md was an unfilled template + tooling/composite had NO verification.md — exactly as the cross-exam predicted | REAL — all three artifacts written the same commit; gate now 4/4 PASS exit 0 | first run of the checker |
| 20 | 2026-11-07 | AGENTS.md rewrite (cross-exam blind-spot #3) | the workflow documentation itself | CLAUDE/GROK pointed agents at upstream song lyrics — every agent's canonical instructions were junk | REAL — replaced with the actual EGM procedure + standing rules; pointer files now resolve to real instructions | commit of record |
| 21 | 2026-11-07 | CI chain-gates step (first live run) | its own install source | pip from the PRIVATE goldfish-gate repo failed on the runner (prompt-script error) — visible failure, not silent | REAL — vendor-pinned 0.2.0 @ 5e31480 (tools/vendor/goldfish-gate-pin + PIN.md provenance); upgrade = owner action with full gate re-run | CI run 42373818607 |
| 22 | 2026-11-07 | CI preflight (c) — change control in reverse | imports.json | the 25-DLL update measured an UNCOMMITTED parallel-checkout build; the committed tree on every branch builds 24 (verified by a clean CI-style build) — CI rejected the constant and protected the committed-tree truth | REAL — reverted to 24 with provenance; re-apply when the udpstats work lands committed (gate EXTRA = the trigger) | CI run 42374193195 + clean rebuild |
>>>>>>> 8d07cd9869d5ad5afec86f77004edf6b49413733
| 23 | 2026-11-07 | CI loop + instrumentation (dnsrig) | self-test failure on runner only | 5-iteration causal chain: invisible CI output -> out_write fallback -> uninitialized rcode -> server counters -> SERVER NOTE showed qname garbage -> missing NULL terminator in _rig_parse_qname (one line) | REAL — fixed 18d75273; CI green | runs 42381287177..42387841195 |
| 24 | 2026-11-07 | same loop | dnsrig lookup + tooling | (a) _r_str_compare misused (version comparator for equality -> _wcsicmp); (b) JSON->heredoc->python escaping injected real newline/form-feed into C literals TWICE -> standing rule: patch scripts are FILES, literals composed via chr() | REAL | same runs |
| 25 | 2026-11-10 | lane merge (bypass-class) | AGENTS.md | the composite lane forked BEFORE the 2026-11-07 governance adoption and still carried upstream placeholder content; merge 19f7da7d took the branch side and silently replaced the adopted EGM procedure, mislabeled "junk" — ledger went dark 9 days | CAUGHT-BY: process re-audit (agent, 2026-11-13), not mechanics | process re-audit finding 1 |
| 26 | 2026-11-10 | CI loop (composite lane) | headless suites + bench probes | phase3 r2 NEEDS-REVISION integrated (a5d5c02c); T012 bench probes "live-run green" (dde35f45); gui gate fix rounds e378ab9c/76e404fc | REAL | composite lane commits |
| 27 | 2026-11-10 | external senior review (fresh agent) | the whole composite effort | verdict SOUND-WITH-CONDITIONS; 4 conditions (empirical testing, S4, no machine-wide audit default, signing re-key); triage was pending | MIXED — 2 integrated, 1 partial, 1 pending (security re-audit 2026-11-17 table) | review-external-senior-2026-11-10.md |
| 28 | 2026-11-10 | RSK-01 fail-closed trigger (as documented) | imports.json | WS2_32.dll re-applied exactly per the row-22 trigger, citing T002 commit 926a4aba (InetPtonW); verified 25/25 against committed tree | REAL — the self-documenting ground-truth rule survived the AGENTS.md clobber | da1eac0b |
| 29 | 2026-11-13 | process re-audit + artifact gate extension | repo tree | 2.2MB build artifacts + scratch committed inside gate-attested commits (test_dns.exe, bin/mergetest/*, tests/dbg3.c); no gate read the tree | REAL — check-chain-artifacts extended with governance markers + tree-hygiene scan; artifacts removed | process re-audit finding 2 |
| 30 | 2026-11-17 | security re-audit (fresh agent) | 24.7K-line composite delta | VERDICT BLOCK: orphan reconcile deletes rule+global filters every apply (enforcement loss); S4 incomplete in applyall; resolver invariant holes; DACL locks user out; phase3 inert-in-binary | REAL — triaged to the composite lane; the RELEASED v3.9.2-hardened.1 predates composite code and is untouched | security re-audit report |
<<<<<<< HEAD

## Anti-pattern counts (recomputed 2026-11-17)

- Reviewer/implementer precision: tracking via rows above (6 wrong-or-missed vs 12+ real catches since adoption of instrumentation).
- Gate bypasses / silent clobbers to date: **2** (row 15 owner-caught; row 25 lane-merge clobber — audit-caught).
- Benches deployed before dispute rather than after: **0 / 3** (still reactive; empirical-arbiter-first rule adopted but not yet mechanical).
- Ledger health: dark 2026-11-10..13 (clobber consequence); healed 2026-11-17 by this commit.

| 29 | 2026-11-17 | fresh-context tooling/release/CI audit (agent 2 of 3) | tool suite + live release chain + CI | VERDICT SOUND-WITH-GAPS: live release chain verified 13/13 END-TO-END with an INDEPENDENT from-scratch ECDSA verifier (sig → artifact pins → Authenticode → version → no upstream URLs); all builds clean; gates live-tested. F-1 MAJOR: signing material burned (password public @ bfe26cc3; cert still signs release + is preflight default) — re-key owed by owner; F-2 MAJOR: SAC blocks local tool exes (compensated: all CI-profile checks independently re-implemented, ALL PASS); F-3 MINOR: released exe = 24 DLLs vs ground truth 25 (expected drift; next release embeds WS2_32); F-4: goldfish CLI drift local 0.3.2 vs pin 0.2.0 (PIN.md claim stale) | REAL | agent report 2026-11-17 |
| 30 | 2026-11-17 | same audit — AGENTS.md accuracy check | governance docs | AGENTS.md verified accurate on 5 sampled claims (gates run, paths exist, msbuild works, binaries allowlist honored); 2 stale spots: SAC sign-after-rebuild mitigation unreliable this session (F-2), PIN.md 0.2.0 claim false (F-4) | REAL | same |
=======
| 31 | 2026-11-17 | fresh-context product security audit (owner-commissioned full-scope, agent 1 of 3) | merged product @ e24a6cfc | VERDICT SOUND-WITH-GAPS: all 25+ hardening claims verified real (zero fake fixes); 3 MAJOR: (1) updater install window fail-open (no re-verify at elevated-exec time, rapp.c:3137-3163) (2) composite_integrity.c FR-12 broken (SetEntriesInAclW result misused as SD + missing user ACE + no PROTECTED flag) (3) notifications IDM_OPENRULESEDITOR mints+applies PERMIT ungated (notifications.c:1883-1947) | REAL — pending EGM fix chain | agent report 2026-11-17 |
| 32 | 2026-11-17 | same audit | release v3.9.2-hardened.1 | the released exe carries finding-1 (install-window TOCTOU, same-user scope) — re-release owed after the fix | REAL | same |
| 33 | 2026-11-17 | PR archaeology (owner asked about GUI work) | PR #12 + master | PR #12 was STALE (head 71bc3c3b = master ancestor): its "diff" was master's own governance work REVERSED — merging would have restored committed binaries + clobbered AGENTS.md. Closed instead. AND: the GUI work the owner remembered EXISTS as a full chain on master: docs/specs/gui/ (design + handoff + mockup-r1.html interactive RTL 6-page + coverage matrix FR-15) @ 71bc3c3b | REAL — stale PR closed; GUI chain confirmed on master | merge-base verification |
| 34 | 2026-11-17 | CI-dispatch protocol (no pre-merge CI on composite branches) | PRs #15/#9/#12 | dispatched smoke-test on each PR head BEFORE merge: #15 green→merged, #9 green→merged, #12 red→diagnosed→closed as stale. Workflow-dispatch-then-merge = the new standing merge protocol for untriggered branches | REAL | runs 43981116802/43981128547/43981139479 |
| 35 | 2026-11-17 | ledger-structure audit (agent 3 of 3) | retrospective-ledger.md itself | DESTRUCTION EVENT #1: heal commit c7de2414 deleted rows 16-22 (cross-exam provenance, DEC-11 reader catch, locked-exe incident, artifact-gate first run, AGENTS.md rationale, vendor-pin CI failure, RSK-01 24-DLL revert) while its message claimed they were "folded back" — false; append-only violated by the very commit claiming a heal | REAL — restored this commit from c7de2414^ | agent-3 report |
| 36 | 2026-11-17 | ledger-structure audit (agent 3) | retrospective-ledger.md | DESTRUCTION EVENT #2: c60ce9c1 (owner lane) overwrote the branch ledger destroying the branch audit rows (product-audit verdict + 3 MAJORs, release-TOCTOU, PR #12 stale archaeology, CI-dispatch protocol run IDs 43981116802/43981128547/43981139479) and re-using numbers 29-30; master row 28 cites a dangling row 22 | REAL — restored this commit from 6d3ef04e; renumbered contiguous | agent-3 report |
| 37 | 2026-11-17 | ledger-structure audit (agent 3) | missed incidents sweep | rows owed but never written, now backfilled: (a) phase2 gate catch 29056ccd (scratch files + key parents, 2026-11-11); (b) 4 failed master CI chain-gate runs of 2026-11-11 (43060201161/43060395995/43062790919/43100187988); (c) RESUME.md staleness (PR #12 guidance) | REAL — backfilled | agent-3 report |
| 38 | 2026-11-17 | stale-lane hazard (agent 3) | composite/T003-T006-prompting | the active lane carried the PRE-HEAL tree (clobbered AGENTS.md, test_dns.exe, bin/mergetest binaries, old checker) — a third clobber-class merge waiting to happen; PR #12 closed as stale (head = master ancestor 71bc3c3b); lane rebase owed before any further merge | REAL | agent-3 report + git merge-base |
>>>>>>> 8d07cd9869d5ad5afec86f77004edf6b49413733

## Standing rule adopted from this ledger (empirical-arbiter-first, roadmap item 1)

> Any BLOCKING finding about observable behavior must attach a reproduction
> (bench, script, or command output) at review time; without one it is
> labeled `hypothesis — non-gating` until arbitrated empirically.
> Precedent: row 6 (a wrong BLOCKING came within one accepted review of
> ratifying a regression).


| 39 | 2026-11-18 | release engineering (G-2+G-3 combined) | v3.9.3-hardened.1 | O-1 CLOSED: signing re-keyed (cert FEC37DA0...83 44D v2, valid 2031-11-18, password generated off-repo, burned cert retired from the gate); O-2 CLOSED: v3.9.3-hardened.1 RELEASED (release id 449359485) - full preflight gate 9/9 PASS on the signed exe (v2 thumbprint match, version 3.9.3, parity 25 DLLs, feed verified via the production verifier) | REAL - release live | release + gate outputs |
| 40 | 2026-11-18 | PR-head race (GitHub eventual consistency) | PR #18 merge | the merge captured the branch head BEFORE the VERSION/VERSION.sig commit landed - master advertised 3.9.2 while the 3.9.3 release+assets were live; caught by post-merge live verification (raw vs master vs artifact hashes); fixed by cherry-pick PR #19 (b32a458c); raw CDN cache delayed visibility ~5 min (verified consistent-stale meanwhile - fail-safe direction) | REAL - closed | PR #19 + raw verification |
| 41 | 2026-11-18 | independent pure-math verifier (arbiter rule) | the LIVE feed pair post-CDN | raw VERSION(3.9.3)+sig verified PASS by a from-scratch secp256r1 verifier - the live signed feed is consistent and authentic | REAL | verification output 2026-11-18 |

## Owner-decision tracker (agent-3: the owner-gated queue was prose-scattered)

| # | Decision | Blocking | Source |
|---|---|---|---|
| O-1 | ~~PFX re-key~~ CLOSED 2026-11-18: cert v2 FEC37DA0...83 44D signs everything; burned cert retired | - | row 39 |
| O-2 | ~~Re-release~~ CLOSED 2026-11-18: v3.9.3-hardened.1 live (id 449359485, exe 0a1d5f44...85ff0) with the 3 MAJOR fixes | - | rows 39-40 |
| O-3 | r6 decision (open the goldfish amendment round or keep frozen) | composite Phase 2 | RESUME frozen-decision |
| O-4 | Product naming (Portcullis / Husn / simplewall CE / defer) | branding only | RESUME item 5 |
| O-5 | goldfish pin upgrade 0.2.0 → 0.3.2 + full gate re-run | CI consistency | audit-2 F-4; PIN.md |
| O-6 | Interactive verification round (blocking-first #2161, #2167, #2163, notifications, uninstall) | Phase 1 release | RESUME item 1 | data (tooling chain, roadmap item 3)

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
<<<<<<< HEAD

=======
| 16 | 2026-11-07 | adversarial cross-examination (2nd agent) | the process audit itself | audit provenance correction: AGENTS.md lyrics are UPSTREAM-inherited (henrypp, 8f625967), not fork pollution; PR #9 vanished + "#" unexpanded var = silent automation failure; tooling chain has NO verification.md at all | REAL — 7 claims VERIFIED / 2 PARTIAL / 0 REFUTED; 3 audit blind-spots identified | cross-exam report, session 2026-11-07 |
| 17 | 2026-11-07 | C preflight DEC-11 strict reader | imports.json provenance note | 334-char note with — escapes exceeded the reader subset — fail-closed as designed | REAL — note shortened to ASCII 162; lesson: ground-truth notes stay ASCII + short | session T009 verification |
| 18 | 2026-11-07 | C preflight fail-closed | locked exe (0xC0000043 sharing violation) | parallel session held the binary mid-build — tool refused instead of reading a torn file | REAL — transient; stable-copy retry passed 9/9 | session T009 verification |
| 19 | 2026-11-07 | check-chain-artifacts.py (roadmap item 1, "best buy") | all 4 chains | tooling handoff.md was an unfilled template + tooling/composite had NO verification.md — exactly as the cross-exam predicted | REAL — all three artifacts written the same commit; gate now 4/4 PASS exit 0 | first run of the checker |
| 20 | 2026-11-07 | AGENTS.md rewrite (cross-exam blind-spot #3) | the workflow documentation itself | CLAUDE/GROK pointed agents at upstream song lyrics — every agent's canonical instructions were junk | REAL — replaced with the actual EGM procedure + standing rules; pointer files now resolve to real instructions | commit of record |
| 21 | 2026-11-07 | CI chain-gates step (first live run) | its own install source | pip from the PRIVATE goldfish-gate repo failed on the runner (prompt-script error) — visible failure, not silent | REAL — vendor-pinned 0.2.0 @ 5e31480 (tools/vendor/goldfish-gate-pin + PIN.md provenance); upgrade = owner action with full gate re-run | CI run 42373818607 |
| 22 | 2026-11-07 | CI preflight (c) — change control in reverse | imports.json | the 25-DLL update measured an UNCOMMITTED parallel-checkout build; the committed tree on every branch builds 24 (verified by a clean CI-style build) — CI rejected the constant and protected the committed-tree truth | REAL — reverted to 24 with provenance; re-apply when the udpstats work lands committed (gate EXTRA = the trigger) | CI run 42374193195 + clean rebuild |
>>>>>>> 8d07cd9869d5ad5afec86f77004edf6b49413733
| 23 | 2026-11-07 | CI loop + instrumentation (dnsrig) | self-test failure on runner only | 5-iteration causal chain: invisible CI output -> out_write fallback -> uninitialized rcode -> server counters -> SERVER NOTE showed qname garbage -> missing NULL terminator in _rig_parse_qname (one line) | REAL — fixed 18d75273; CI green | runs 42381287177..42387841195 |
| 24 | 2026-11-07 | same loop | dnsrig lookup + tooling | (a) _r_str_compare misused (version comparator for equality -> _wcsicmp); (b) JSON->heredoc->python escaping injected real newline/form-feed into C literals TWICE -> standing rule: patch scripts are FILES, literals composed via chr() | REAL | same runs |
| 25 | 2026-11-10 | lane merge (bypass-class) | AGENTS.md | the composite lane forked BEFORE the 2026-11-07 governance adoption and still carried upstream placeholder content; merge 19f7da7d took the branch side and silently replaced the adopted EGM procedure, mislabeled "junk" — ledger went dark 9 days | CAUGHT-BY: process re-audit (agent, 2026-11-13), not mechanics | process re-audit finding 1 |
| 26 | 2026-11-10 | CI loop (composite lane) | headless suites + bench probes | phase3 r2 NEEDS-REVISION integrated (a5d5c02c); T012 bench probes "live-run green" (dde35f45); gui gate fix rounds e378ab9c/76e404fc | REAL | composite lane commits |
| 27 | 2026-11-10 | external senior review (fresh agent) | the whole composite effort | verdict SOUND-WITH-CONDITIONS; 4 conditions (empirical testing, S4, no machine-wide audit default, signing re-key); triage was pending | MIXED — 2 integrated, 1 partial, 1 pending (security re-audit 2026-11-17 table) | review-external-senior-2026-11-10.md |
| 28 | 2026-11-10 | RSK-01 fail-closed trigger (as documented) | imports.json | WS2_32.dll re-applied exactly per the row-22 trigger, citing T002 commit 926a4aba (InetPtonW); verified 25/25 against committed tree | REAL — the self-documenting ground-truth rule survived the AGENTS.md clobber | da1eac0b |
| 29 | 2026-11-13 | process re-audit + artifact gate extension | repo tree | 2.2MB build artifacts + scratch committed inside gate-attested commits (test_dns.exe, bin/mergetest/*, tests/dbg3.c); no gate read the tree | REAL — check-chain-artifacts extended with governance markers + tree-hygiene scan; artifacts removed | process re-audit finding 2 |
| 30 | 2026-11-17 | security re-audit (fresh agent) | 24.7K-line composite delta | VERDICT BLOCK: orphan reconcile deletes rule+global filters every apply (enforcement loss); S4 incomplete in applyall; resolver invariant holes; DACL locks user out; phase3 inert-in-binary | REAL — triaged to the composite lane; the RELEASED v3.9.2-hardened.1 predates composite code and is untouched | security re-audit report |
<<<<<<< HEAD

## Anti-pattern counts (recomputed 2026-11-17)

- Reviewer/implementer precision: tracking via rows above (6 wrong-or-missed vs 12+ real catches since adoption of instrumentation).
- Gate bypasses / silent clobbers to date: **2** (row 15 owner-caught; row 25 lane-merge clobber — audit-caught).
- Benches deployed before dispute rather than after: **0 / 3** (still reactive; empirical-arbiter-first rule adopted but not yet mechanical).
- Ledger health: dark 2026-11-10..13 (clobber consequence); healed 2026-11-17 by this commit.

| 29 | 2026-11-17 | fresh-context tooling/release/CI audit (agent 2 of 3) | tool suite + live release chain + CI | VERDICT SOUND-WITH-GAPS: live release chain verified 13/13 END-TO-END with an INDEPENDENT from-scratch ECDSA verifier (sig → artifact pins → Authenticode → version → no upstream URLs); all builds clean; gates live-tested. F-1 MAJOR: signing material burned (password public @ bfe26cc3; cert still signs release + is preflight default) — re-key owed by owner; F-2 MAJOR: SAC blocks local tool exes (compensated: all CI-profile checks independently re-implemented, ALL PASS); F-3 MINOR: released exe = 24 DLLs vs ground truth 25 (expected drift; next release embeds WS2_32); F-4: goldfish CLI drift local 0.3.2 vs pin 0.2.0 (PIN.md claim stale) | REAL | agent report 2026-11-17 |
| 30 | 2026-11-17 | same audit — AGENTS.md accuracy check | governance docs | AGENTS.md verified accurate on 5 sampled claims (gates run, paths exist, msbuild works, binaries allowlist honored); 2 stale spots: SAC sign-after-rebuild mitigation unreliable this session (F-2), PIN.md 0.2.0 claim false (F-4) | REAL | same |
=======
| 31 | 2026-11-17 | fresh-context product security audit (owner-commissioned full-scope, agent 1 of 3) | merged product @ e24a6cfc | VERDICT SOUND-WITH-GAPS: all 25+ hardening claims verified real (zero fake fixes); 3 MAJOR: (1) updater install window fail-open (no re-verify at elevated-exec time, rapp.c:3137-3163) (2) composite_integrity.c FR-12 broken (SetEntriesInAclW result misused as SD + missing user ACE + no PROTECTED flag) (3) notifications IDM_OPENRULESEDITOR mints+applies PERMIT ungated (notifications.c:1883-1947) | REAL — pending EGM fix chain | agent report 2026-11-17 |
| 32 | 2026-11-17 | same audit | release v3.9.2-hardened.1 | the released exe carries finding-1 (install-window TOCTOU, same-user scope) — re-release owed after the fix | REAL | same |
| 33 | 2026-11-17 | PR archaeology (owner asked about GUI work) | PR #12 + master | PR #12 was STALE (head 71bc3c3b = master ancestor): its "diff" was master's own governance work REVERSED — merging would have restored committed binaries + clobbered AGENTS.md. Closed instead. AND: the GUI work the owner remembered EXISTS as a full chain on master: docs/specs/gui/ (design + handoff + mockup-r1.html interactive RTL 6-page + coverage matrix FR-15) @ 71bc3c3b | REAL — stale PR closed; GUI chain confirmed on master | merge-base verification |
| 34 | 2026-11-17 | CI-dispatch protocol (no pre-merge CI on composite branches) | PRs #15/#9/#12 | dispatched smoke-test on each PR head BEFORE merge: #15 green→merged, #9 green→merged, #12 red→diagnosed→closed as stale. Workflow-dispatch-then-merge = the new standing merge protocol for untriggered branches | REAL | runs 43981116802/43981128547/43981139479 |
| 35 | 2026-11-17 | ledger-structure audit (agent 3 of 3) | retrospective-ledger.md itself | DESTRUCTION EVENT #1: heal commit c7de2414 deleted rows 16-22 (cross-exam provenance, DEC-11 reader catch, locked-exe incident, artifact-gate first run, AGENTS.md rationale, vendor-pin CI failure, RSK-01 24-DLL revert) while its message claimed they were "folded back" — false; append-only violated by the very commit claiming a heal | REAL — restored this commit from c7de2414^ | agent-3 report |
| 36 | 2026-11-17 | ledger-structure audit (agent 3) | retrospective-ledger.md | DESTRUCTION EVENT #2: c60ce9c1 (owner lane) overwrote the branch ledger destroying the branch audit rows (product-audit verdict + 3 MAJORs, release-TOCTOU, PR #12 stale archaeology, CI-dispatch protocol run IDs 43981116802/43981128547/43981139479) and re-using numbers 29-30; master row 28 cites a dangling row 22 | REAL — restored this commit from 6d3ef04e; renumbered contiguous | agent-3 report |
| 37 | 2026-11-17 | ledger-structure audit (agent 3) | missed incidents sweep | rows owed but never written, now backfilled: (a) phase2 gate catch 29056ccd (scratch files + key parents, 2026-11-11); (b) 4 failed master CI chain-gate runs of 2026-11-11 (43060201161/43060395995/43062790919/43100187988); (c) RESUME.md staleness (PR #12 guidance) | REAL — backfilled | agent-3 report |
| 38 | 2026-11-17 | stale-lane hazard (agent 3) | composite/T003-T006-prompting | the active lane carried the PRE-HEAL tree (clobbered AGENTS.md, test_dns.exe, bin/mergetest binaries, old checker) — a third clobber-class merge waiting to happen; PR #12 closed as stale (head = master ancestor 71bc3c3b); lane rebase owed before any further merge | REAL | agent-3 report + git merge-base |
>>>>>>> 8d07cd9869d5ad5afec86f77004edf6b49413733

## Standing rule adopted from this ledger (empirical-arbiter-first, roadmap item 1)

> Any BLOCKING finding about observable behavior must attach a reproduction
> (bench, script, or command output) at review time; without one it is
> labeled `hypothesis — non-gating` until arbitrated empirically.
> Precedent: row 6 (a wrong BLOCKING came within one accepted review of
> ratifying a regression).


| 39 | 2026-11-18 | release engineering (G-2+G-3 combined) | v3.9.3-hardened.1 | O-1 CLOSED: signing re-keyed (cert FEC37DA0...83 44D v2, valid 2031-11-18, password generated off-repo, burned cert retired from the gate); O-2 CLOSED: v3.9.3-hardened.1 RELEASED (release id 449359485) - full preflight gate 9/9 PASS on the signed exe (v2 thumbprint match, version 3.9.3, parity 25 DLLs, feed verified via the production verifier) | REAL - release live | release + gate outputs |
| 40 | 2026-11-18 | PR-head race (GitHub eventual consistency) | PR #18 merge | the merge captured the branch head BEFORE the VERSION/VERSION.sig commit landed - master advertised 3.9.2 while the 3.9.3 release+assets were live; caught by post-merge live verification (raw vs master vs artifact hashes); fixed by cherry-pick PR #19 (b32a458c); raw CDN cache delayed visibility ~5 min (verified consistent-stale meanwhile - fail-safe direction) | REAL - closed | PR #19 + raw verification |
| 41 | 2026-11-18 | independent pure-math verifier (arbiter rule) | the LIVE feed pair post-CDN | raw VERSION(3.9.3)+sig verified PASS by a from-scratch secp256r1 verifier - the live signed feed is consistent and authentic | REAL | verification output 2026-11-18 |

## Owner-decision tracker (agent-3: the owner-gated queue was prose-scattered)

| # | Decision | Blocking | Source |
|---|---|---|---|
| O-1 | ~~PFX re-key~~ CLOSED 2026-11-18: cert v2 FEC37DA0...83 44D signs everything; burned cert retired | - | row 39 |
| O-2 | ~~Re-release~~ CLOSED 2026-11-18: v3.9.3-hardened.1 live (id 449359485, exe 0a1d5f44...85ff0) with the 3 MAJOR fixes | - | rows 39-40 |
| O-3 | r6 decision (open the goldfish amendment round or keep frozen) | composite Phase 2 | RESUME frozen-decision |
| O-4 | Product naming (Portcullis / Husn / simplewall CE / defer) | branding only | RESUME item 5 |
| O-5 | goldfish pin upgrade 0.2.0 → 0.3.2 + full gate re-run | CI consistency | audit-2 F-4; PIN.md |
| O-6 | Interactive verification round (blocking-first #2161, #2167, #2163, notifications, uninstall) | Phase 1 release | RESUME item 1 |
