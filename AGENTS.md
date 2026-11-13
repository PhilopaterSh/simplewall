# AGENTS.md - composite fork governance (rewritten 2026-11-10)

> The previous file at this path contained unrelated junk content and was
> not a real instruction file; it was replaced. Agents working in this
> repository follow THIS file plus `docs/specs/composite/RESUME.md`.

## Read first, always

1. `docs/specs/composite/RESUME.md` - the canonical resume pointer. Never
   restart from scratch; build on the latest reached state.
2. `docs/BACKLOG.md` - mined upstream issues, P1 status, and the composite
   vision tracker (14 rows).
3. `docs/specs/composite/design.md` - the approved umbrella design (r5).
   `design-r6-draft.md` stays FROZEN until the owner opens it.

## Hard rules

- **Owner gates.** Interactive verification, PR merges (#9 -> #11 -> #12),
  the r6 decision, product naming, and the PFX re-key belong to the owner.
  Do not perform, simulate, or pre-empt any of them.
- **Goldfish chain.** Every design change goes: design -> fresh-context
  review -> owner approval -> spec/plan/tasks -> gate exit 0. Subagent
  research is welcome BEFORE drafting; it never replaces the chain.
- **Upstream hygiene.** All composite code is fork-namespaced
  (`composite_*.c` modules) and sidecar state lives outside `profile.xml`
  (DEC-09, DATA-01). Monthly upstream rebases must stay cheap; if a change
  would conflict with that, stop and design it.
- **Locks and UI threads.** Never hold `lock_state` / `lock_publisher` /
  `lock_transaction` across any call that can message a window (S4/P1-1).
  Snapshot under the lock, work outside it.
- **Verify before claiming.** Build with the MSVC toolchain and report the
  actual result. Subagent verdicts are inputs, not proof - re-run tests
  yourself before adopting (rule from the 2026-11-10 arena rounds).
- **Signing material is burned.** The PFX password is public in history
  (commit bfe26cc3). Treat all signing claims as void until the owner
  re-keys. Never reference or reuse the leaked material.
- **Secrets.** Never commit credentials, tokens, or private data.

## Build

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
msbuild simplewall.sln -property:Configuration=Release -property:Platform=x64 -property:PlatformToolset=v143 -verbosity:minimal -m
```
(The project targets toolset v145/VS 2026 where available; v143 override is
the verified fallback on this machine.)


## Composite addendum (2026-11-10, merged from the composite branch)

- **Locks and UI threads:** never hold `lock_state` / `lock_publisher` /
  `lock_transaction` across any call that can message a window (S4/P1-1);
  snapshot under the lock, work outside it.
- **Signing material is burned:** the old PFX password is public in pushed
  history (bfe26cc3). Treat all signing claims as void until the owner
  re-keys; never reuse the leaked material.
- **Verify subagent output:** subagent verdicts are inputs, not proof —
  rebuild and re-run tests yourself before adopting (rule proven by the
  2026-11-10 arena rounds).
- **v143 build fallback:** where VS 2026 (v145 toolset) is absent, the
  verified build is `msbuild ... -property:PlatformToolset=v143`.
