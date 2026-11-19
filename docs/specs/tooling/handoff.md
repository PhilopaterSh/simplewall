# Handoff: Tooling Round — Own Release Preflight + Feed DNS Rig (r3)

> Generated from design.md r3 (owner scope pick A recorded; language
> unification to C recorded verbatim). This handoff replaces the
> scaffold template left behind by r1/r2 — flagged by
> tools/check-chain-artifacts.py (process-audit roadmap item 1).

## Problem

The fork's release path and feed verification depended on closed-source
tools (pestudio license forbids the use case; Sysinternals closed) and
on ad-hoc session scripts. The update-feed positive control had no
offline harness at all.

## Intended outcomes

1. One-command binary preflight gate (Authenticode, embedded-key
   integrity vs off-repo ground truth, import parity, version, SWC1
   blocklist, PE flags) — fail-closed, CI-usable, zero private material
   in CI (DEC-07).
2. Offline feed harness: DNS rig (NXDOMAIN-default) + TLS feed server so
   the app's own updater verifies the signed feed in a sandbox.
3. Tooling in the program's own language (C via vendored routine —
   DEC-08), with preflight calling the production verifier (DEC-09).

## Decisions carried (see design.md r3 for full text)

DEC-01..DEC-11, RSK-01..RSK-05 — especially: python versions retire once
the C tools re-pass AS1-AS9 (DEC-08); per-tool vcxproj, SubSystem=
Console + APP_CONSOLE + wmain, no CppWinRT (DEC-10); minimal-JSON
ground-truth reader, fail-closed outside subset (DEC-11); vendor touch
limited to the 2-line verifier export (DEC-09/RSK-05).

## Owner approval

- Scope: in-session interview option pick — "A: preflight + dnsrig"
  (2026-11-07, recorded in design.md r2 header).
- Language: session directive recorded verbatim in design.md r3 header
  («...توحيد عمليات الكود في نفس لغة البرنامج...»).
