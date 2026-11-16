# AGENTS.md - composite fork governance (merged 2026-11-13)

> Provenance correction: the file this one replaced was NOT junk — it was
> the adopted 2026-11-07 EGM governance rewrite (bfe26cc3), silently lost
> on 2026-11-10 when the composite lane (forked before adoption, still
> carrying upstream's placeholder content) merged and took the branch side
> (77eea331 -> merge 19f7da7d). This revision MERGES both eras: the EGM
> cycle + standing rules from 2026-11-07 and the composite governance from
> 2026-11-10. Agents follow THIS file plus `docs/specs/composite/RESUME.md`.

## Read first, always

1. `docs/specs/composite/RESUME.md` - the canonical resume pointer. Never
   restart from scratch; build on the latest reached state (updated at
   every milestone, not retroactively).
2. `docs/BACKLOG.md` - mined upstream issues, P1 status, and the composite
   vision tracker.
3. `docs/specs/composite/design.md` - the approved umbrella design (r5).
   `design-r6-draft.md` stays FROZEN until the owner opens it.
4. `docs/specs/tooling/retrospective-ledger.md` - the append-only
   effectiveness ledger. Every gate catch, review finding (REAL/WRONG +
   arbitration), bypass, and silent-automation failure gets a row.

## The EGM cycle - mandatory for every feature/fix

1. Elephant drafts `docs/specs/<chain>/design.md` (revision header).
2. Fresh-context goldfish review returns VERDICT APPROVE /
   APPROVE-WITH-CHANGES / BLOCK; integrate before freezing.
3. Owner approval recorded VERBATIM in the design header.
4. spec.md / plan.md / tasks.md generated from the approved design.
5. Mechanical gate exit 0 BEFORE any implementation commit:
   `goldfish check design.md spec.md plan.md tasks.md`
   (CI runs the same gate + tools/check-chain-artifacts.py per push).
6. Implement only chain tasks; re-run gates after.
7. PR -> CI green (chain gates + build + launch + C preflight --ci +
   dnsrig self-test) -> merge. Direct-to-master pushes are bypass-class
   events and get a ledger row.

## Standing rules (each earned by a recorded incident)

- **Empirical-arbiter-first.** Any BLOCKING claim about observable
  behavior must attach a reproduction (bench/script/output) at review
  time; without one it is `hypothesis - non-gating`. Precedent: a wrong
  BLOCKING ("CNG wants little-endian") came within one accepted review of
  ratifying a regression; tools/cng-signature-bench.py refuted it in
  seconds and is the standing RSK-04 gate (exit 0 before any
  feed/signature change).
- **Never trust docs/memory for byte-order or ABI claims** - prove
  against the real API first.
- **Owner adversarial question per round** - the owner's unsolicited
  challenge is a formal detection mechanism (it caught the one gate
  bypass and spawned the supply-chain round). Log it in the ledger when
  it fires.
- **Lanes.** One worktree per lane; never commit across lanes; the tools
  lane never refactors vendor/ (tools adapt to vendor); vendor changes
  are minimal diffs acked against the vendor lane's live state (measure
  mtime + git log before racing). REBASE working lanes onto master after
  every adoption - a stale lane merge can silently revert governance and
  ground-truth files (the 2026-11-10 AGENTS.md clobber; the imports.json
  staged revert caught by CI).
- **Amendment propagation.** When a revision header CORRECTS an earlier
  statement, grep the body for the superseded term and rewrite it in the
  same revision (incident: DEC-05 body contradicted the r4 header).
- **Artifact completeness.** No implementation while any chain file is a
  template or verification.md is missing; CI enforces via
  tools/check-chain-artifacts.py (which also pins AGENTS.md markers).
- **Ledger is append-only and alive.** A row per incident within 24h of
  the fix; anti-pattern counts recomputed at each audit. A dark ledger
  is a workflow-health alarm (0 rows for 9 days after the 2026-11-10
  clobber).
- **Sign after every rebuild** (SAC): signtool /fd SHA256 /f
  D:/CV/Github/.keys/fork-codesign.pfx (password NOT committed anywhere;
  password-file pattern only). NEVER commit credentials or passwords.
- **Tree hygiene.** No binaries (*.exe/*.map/*.obj/*.pdb), no scratch
  files (dbg*), nothing >256KB outside the explicit allowlist
  (bin/profile_internal.bin) - CI enforces via check-chain-artifacts.py
  tree scan (incident: test_dns.exe + bin/mergetest artifacts committed
  inside gate-attested commits).
- **RSK-01 provenance.** Parity constants live in
  tools/preflight-ground-truth/*.json; update ONLY with a commit citing
  the diff that changed the underlying binary, against a COMMITTED tree
  (an uncommitted local build once poisoned the constant; CI caught it).

## Composite hard rules (2026-11-10, preserved)

- **Owner gates.** Interactive verification, the r6 decision, product
  naming, and the PFX re-key belong to the owner. Do not perform,
  simulate, or pre-empt any of them.
- **Upstream hygiene.** All composite code is fork-namespaced
  (`composite_*.c`); sidecar state lives outside `profile.xml`
  (DEC-09, DATA-01). Monthly upstream rebases must stay cheap.
- **Locks and UI threads.** Never hold `lock_state` / `lock_publisher` /
  `lock_transaction` across any call that can message a window (S4/P1-1).
  Snapshot under the lock, work outside it.
- **Verify before claiming.** Build with the MSVC toolchain and report
  the actual result. Subagent verdicts are inputs, not proof - re-run
  tests yourself before adopting (2026-11-10 arena rounds).
- **Signing material is burned.** The PFX password is public in history
  (bfe26cc3). Treat all signing claims as void until the owner re-keys.
  Never reference or reuse the leaked material; passwords live in a
  credential file outside the repo, never in commit messages.
- **Secrets.** Never commit credentials, tokens, or private data.

## Build

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
msbuild simplewall.vcxproj -property:Configuration=Release -property:Platform=x64 -property:PlatformToolset=v143 -verbosity:minimal -m
```
(The project targets v145/VS 2026 where available; the v143 override is
the verified fallback. Tools build per-tool: tools/<name>.vcxproj, no
NuGet needed.)

