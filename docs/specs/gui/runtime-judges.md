# Runtime judges — how fresh composite builds get executed (the SAC problem)

> 2026-11-20. The blocker rearrangement the owner asked for: CI is
> owner-blocked (Actions dispatch 422 persists after the API-layer
> re-enable), SAC blocks fresh builds on the host. This document ranks
> the verified paths to a runtime verdict, WITH SOURCES, and records
> the paths the research killed.

## The problem class (sourced)

- SAC re-rolls a per-hash cloud verdict on EVERY rebuild; there is NO
  per-application developer exception for repeatedly rebuilt unsigned
  binaries ([Microsoft Q&A](https://learn.microsoft.com/en-sg/answers/questions/6033458/windows-11-smart-app-control-how-to-safely-test-un)).
- Blocked files get no "run anyway" option ([r/gamedev](https://www.reddit.com/r/gamedev/comments/1x9pxvn/game_blocked_by_smart_app_control));
  this matches the owner's two screenshots (bash.exe loading
  simplewall.exe blocked by Windows Security).

## Paths the research KILLED (do not spend time here)

- **Windows Sandbox (.wsb)**: SAC blocks PERSIST inside the sandbox —
  the sandbox inherits the host's security policy and there is no
  official SAC toggle inside it ([Microsoft Learn
  answers](https://learn.microsoft.com/en-us/answers/questions/5641557/how-do-you-turn-off-smart-app-control-in-windows-s));
  some setups cannot even START the sandbox while SAC is enabled;
  "You need to install an app for this task" failures inside the
  sandbox trace to the same policy inheritance ([Super
  User](https://superuser.com/questions/1778342/windows-sandbox-wont-open-executables-you-need-to-install-an-app-for-this-ta)).
  NOT built (2026-11-20, before spending the effort).
- **Disabling SAC on the host**: owner declined explicitly (he does
  not want to manage the host without SAC) - permanently out.

## The verified judges (ranked)

### 1. Full VM without SAC configured (Hyper-V) - RECOMMENDED local judge

A fresh Windows VM simply has no SAC state (SAC is a host-client
policy); running SAC-blocked fresh builds inside a full VM is the
community-recommended workaround ([PrePoMax
forum](https://prepomax.discourse.group/t/prepomax-3-0-0-blocked-by-windows-smart-app-control-usercontrols-dll-error/3849)).
One-time owner cost: enable Hyper-V (admin PowerShell +
reboot), create one VM with any Windows ISO (an EVAL Server ISO also
answers Finding 8's Server-2025 question directly - same OS class as
the runner where the freeze reproduced).
In-VM runner: `tools/local-judge-vm.ps1` - mirrors the CI selftest
step 1:1 (75s watchdog, LocalDumps, comsvcs dump + screenshot on
hang, breadcrumbs, then the gui testdrive on green) so a VM verdict
is directly comparable to a runner verdict.

### 2. CI (the runner) - already instrumented, owner-gated

The cdb-on-hang step (d9bf66e5) is committed and YAML-validated; the
moment Actions dispatch works (owner: Settings -> Actions -> allow,
check spending limit if private), the next run verifies the Finding-8
fix green - or prints the symbolized stacks if anything still hangs.

### 3. The owner's host click-through - the decisive SHELL test

Independent of the judges above: the owner manually runs the fresh
build and clicks through the SAC prompt once (SAC asks once per
hash). This is also the ONLY judge that exercises the real desktop
(DPI, themes, RTL) - the M1/M2 checklist in testing-record.md +
docs/specs/gui/handoff.md AC-G-1..6.

### 4. Alternative CI providers (account-layer, deferred to owner pick)

Azure Pipelines (windows-2025 image = the same Server-2025 OS class
where Finding 8 reproduced) or AppVeyor (free Windows CI for OSS)
would give an Actions-independent judge; both need the owner's
sign-in to enable, so this is an interview-style decision, not
something to do unilaterally. Prep on request only.
