# RESUME — canonical session-start pointer

> **REFRESHED 2026-11-21** (the chain is GREEN on the verifier lane).
> Read this FIRST in any new session; refresh at each milestone.

## CURRENT STATE (feat/gui-g1, PR #24 open — MERGE-READY)

- **THE VERIFICATION CHAIN IS GREEN** (run 44860140693, 2026-11-21,
  fork head 8150f18e): chain gates + build + composite selftest
  (TOTAL: 0 failures, exit code = the failure count) + gui-testdrive
  (8/8 page screenshots incl. the light theme) ALL SUCCESS.
- The judge = the verifier lane on the owner's OTHER repo
  (Ph.Sh-Subdomain sw-verifier.yml, dispatch with an explicit fork
  SHA), because the fork's own Actions dispatch is repo-blocked (422
  desync; every API lever exhausted — docs/specs/gui/runtime-judges.md).
  Twelve runs took the chain from crash → 23 real failures → 0.
- SIX root-cause classes found and fixed en route (Findings 5/8/10 in
  testing-record.md): (1) the borrowed-pointer UAF in packs_getpath
  (the freeze — Finding 8 CLOSED), (2) the borrowed-finalstringbuilder
  dereference ×5 (the exit fastfail — Finding 5 CLOSED; three of the
  five were LATENT CORRUPTION in the RELEASED v3.9.4), (3) byte/char
  confusion ×5 sidecar writers, (4) HeapReAlloc-NULL ×4 snapshot grows
  + addhashtableitem's drop-update, (5) the filter-line writer/parser
  format mismatch, (6) NTFS mtime coarseness → (mtime, SIZE) keys.
- THE NEXT SIGNED RELEASE MUST CARRY THESE FIXES — the released
  v3.9.4's sidecar writes corrupt the heap (latent).
- G-1/G-2/G-3 implemented + screenshot-proven on the runner desktop
  (RTL rail, chips, search, all 6 pages + light theme); G-4 partial
  (IsShellRtl config-driven; upstream dialog phase-out DEFERRED —
  destructive, now unblocked by the green runtime evidence); G-5
  runtime-verified.
- Instruments standing: -gui-selftest (exit code = failure count),
  gui-testdrive.ps1 (EnumWindows window find — FindWindowW
  deterministically fails on runners), the verifier lane
  (sw-verifier.yml + sw_ref SHA input), dump-analyze.py, the cdb
  post-mortem step, runtime-judges.md (sourced judge decisions).

## NEXT STEPS (in order)

1. OWNER: merge PR #24 (green on the lane; the fork's own Actions
   stays blocked until the one-click fix — the fork-activation banner
   or the personal selected-repositories policy).
2. OWNER: run the fresh build locally (SAC click-through) — the M1/M2
   checklist (testing-record.md + docs/specs/gui/handoff.md AC-G-1..6)
   — the interactive shell acceptance.
3. G-4 remainder: upstream dialog phase-out (the runtime evidence now
   exists; still destructive — do it on a fresh branch).
4. G-5 final: the next signed release MUST carry the Findings-5/10
   fixes (three latent-corruption sites in the released v3.9.4).

## STANDING RULES (paid for repeatedly)

- chr(92) discipline: python heredocs + Windows paths = escape hell
  (octal  -> 0x08,  -> 0x08, d -> 'd') - byte-repair +
  YAML-validate after ANY path-bearing script. THREE incidents logged.
- CWD drift: ALWAYS cd to the repo root first + pwd; a cwd-scoped
  rm/add swept docs/ once (recovered from the parent commit, third
  row-29-class event). USE ABSOLUTE PATHS IN TOOLS.
- _r_sys_getopt matches by PREFIX; ordering of verb checks matters.
- SAC verdicts are per-hash cloud calls: EVERY rebuild re-rolls the
  verdict; sign after every rebuild AND expect blocks anyway.
- APP_NO_GUEST lives in the VCXPROJ defines, not rconfig.h.
- Routine path accessors (_r_app_getprofiledirectory/_r_app_getdirectory/
  _r_app_getlogpath) return BORROWED pointers - NEVER dereference the
  result (Finding 8's root cause; see testing-record.md).

> Canonical resume pointer for this fork's composite work. Update at every
> milestone. Last updated: 2026-11-20 (Finding 8 root cause found+fixed).
> Purpose: the work must be resumable from a brand-new session with zero
> dependence on any chat session surviving in a UI sidebar.

## Where the chain stands

- Umbrella design: `docs/specs/composite/design.md` — approved **r5** (owner
  approval recorded verbatim in its header; Arabic, do not paraphrase it).
- Phase 1 chain: `spec.md` / `plan.md` / `tasks.md` (T000–T016), `handoff.md`
  (AC-1..AC-11). All goldfish-gate checks exit 0.
- Implemented on branch `composite/T003-T006-prompting` (in sync with origin):
  T001 audit lifecycle, T002 5157 pipeline, T003–T006 smart prompting
  (tiers/publisher/durations/single-flight) + UDP PID-reuse guards; the
  2026-11-10 wave added T007 lockdown (DEC-04 full recipe), T008/T009
  signed packs (BCrypt P-256 + watermarks + hash-checked sidecar), T011
  tray/status surfaces, T012 bench probes, T013 verification.md, T014
  /W4+/analyze (one documented residual), and a fresh goldfish-gate run
  (exit 0). Remaining in-chain: T010 packs repo (owner: new repository).
- Open PRs (merge in this order): **#9 (T001) → #11 (T002) → #12 (T003–T006)**.
  PRs #1–#7 already merged.

## Verification record

- **Round 1** (2026-11-07): adversarial review of the implemented code —
  verdict EFFECTIVE-WITH-GAPS. Headline: the 5157 pipeline is INERT as shipped
  (`IsCompositeAuditEnabled` / `IsCompositeEventLogEnabled` are read at
  wfp.c:2189/2225, main.c:3692, composite_audit.c:503 but never written
  anywhere). 14 defects ranked; top: S4 UI-hang (confirmed + exit-path
  variant), dead health checker, inbound port swap, session re-prompt loop,
  WinVerifyTrust amplification. See `docs/BACKLOG.md` §P1.
- **Round 2** (2026-11-07): hostile verification of the proposed r6 transport
  inversion — verdict SOUND-WITH-GAPS (G1–G8; upstream evidence #2114,
  #1807, #2132, #2085). Two proposal errors caught and corrected by the
  round: no `subLayerId` field exists in net-event structs; the
  enumTemplate cannot scope by event type.
- **External senior review** (2026-11-10): independent fresh-context
  assessment (reverse-engineering / netsec / pentest / SWE perspective,
  `review-external-senior-2026-11-10.md`) — verdict **SOUND-WITH-CONDITIONS**
  (medium-high confidence). Top conditions: BENCH end-to-end never run yet
  (make it a merge gate), S4 fix before any release, signing re-key before
  any public release, audit policy stays opt-in-only, ship Phase 1 only.
  New r6 gaps found: 60 s fallback-latency window unstated, net-event queue
  completeness untested under flood, 5157 single-slot dedup storm until
  T017. FR-14 should be marked aspirational, not contractual. Triage pending
  owner.

## Frozen decision: r6 (awaiting owner)

- `docs/specs/composite/design-r6-draft.md` — DEC-10 dual transport (net-event
  primary subscribed once per engine lifetime; 5157 fallback with
  engagement/retreat + hysteresis; 4-state tray), new `composite_feed.c`
  module, tasks T017–T024, 7-step BENCH protocol, 6 open questions for the
  goldfish round. Never implemented before owner approval.
- Recommended sequence: keep r6 frozen until the open chain merges, then run
  the r5→r6 goldfish amendment round.

## Pending on the owner (in order)

1. Interactive verification of `bin/64/simplewall.exe` (blocking-first #2161,
   resize-storm #2167, reboot persistence #2163, notification baseline,
   uninstall flow).
2. Merge clicks: #9 (merged 2ea0146c) → #11 (merged) → #12 CLOSED as stale (head = master ancestor; content already on master via the composite lane direct-merges — see ledger rows 27/34).
3. r6 decision (open the goldfish round, or keep frozen).
4. P1 fixes before any Phase 1 release: S4 FIXED 2026-11-10 (detach-under-
   lock/destroy-outside in composite_state.c + composite_publisher.c),
   inbound port swap FIXED 2026-11-10 (composite_eventlog.c: ports now
   follow the same is_inbound endpoint mapping as the addresses), S5 doc
   fix applied. Remaining P1s: S3 held-pending counter coherence. Runtime
   confirmation owed by the owner interactive verification round.
5. Naming decision (Portcullis / Husn / simplewall CE / defer) — release
   branding only.
6. PFX password re-key (password is public in pushed history, commit
   bfe26cc3).

## Key file map

- Design/chain: `docs/specs/composite/{design,spec,plan,tasks,handoff}.md`
- r6 draft: `docs/specs/composite/design-r6-draft.md`
- Backlog / P1s: `docs/BACKLOG.md`
- Fork identity + roadmap: `README.md`

## How to resume in a NEW session

1. The persistent memory index auto-loads and points here — read this file,
   `docs/BACKLOG.md`, and the `design.md` header.
2. Confirm tree state: `git status -sb && git log --oneline -5` in
   `D:\CV\Github\simplewall` (measure before racing a parallel session).
3. Standing instruction: never restart from scratch — build on the latest
   reached state, research with subagents first, keep everything through the
   goldfish-gate chain (design → fresh-context review → owner approval →
   spec/plan/tasks → gate exit 0).
