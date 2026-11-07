# Backlog — mined from upstream issues (henrypp/simplewall), 2026-11-07

Prioritized by impact on THIS fork. Sources: upstream issue tracker (the community's
live requirement signal). Items marked [fixed] are already handled in this fork.

## Done

- **#2167** [fixed] UI stack-overflow crash (WM_SIZE ↔ RBN_HEIGHTCHANGE recursion, ~11k
  frames, c0000005) — reentrancy guard added in `DlgProc` (src/main.c); the second
  destabilizer (forced rebar WM_SIZE) was already disabled in this tree (controls.c).
  Upstream fix contribution candidate (upstream-clean version).

## Compatibility audits (affect our code paths)

- **#2123** Per-user services with `_LUID` suffixes (Win11 25H2): service name/SID
  changes every session → per-service rules stop matching after reboot. Our
  `packages.c` service-SID enumeration has the same exposure. Real fix = rule-name
  normalization design (strip `_LUID` suffix on match, or bind to the template
  service) → fold into Phase 2 rule-model work. Interim: documented limitation.
- **#2161** 3.9.1 regression "filters don't block" — must be covered by the
  interactive verification checklist (test blocking first, before anything else).
- **#2163** Win11 26H2 admin-protection: settings/autostart persistence loss —
  covered by the verification checklist (reboot test).
- **#2135** Idle memory growth (months) — long-run watch; add to release soak notes.

## Investigation queue

- **#2124** Traffic blocked despite an existing HTTP allow rule (Logitech G Hub) —
  possible rule-matching defect; verify our engine on the same scenario.
- **#2041 / #2154** "Access denied" (0x5) on filter operations — interacts with our
  engine-DACL hardening; confirm our security changes don't produce new denial paths.

## Composite backlog (pack/feature ideas from the mine)

- **Virtual-Networking survival pack**: hotspot (#425 — 60 comments, the single most
  discussed issue!), Hyper-V (#1989), VPN split-tunneling (#1999) — pre-built allow
  rules as a signed pack; the largest accumulated user pain in the tracker.
- **svchost containment** (#1820): per-caller svchost control — extends service-level
  filtering; pairs with Phase 2 rule model.
- UX niceties (low priority): pin apps (#2160), regex search (#2140), comments tab
  (#2061), copy multi-line alerts (#2064), scoped CTRL+A (#2071).

## Security ecosystem notes

- **#1954**: `simplewall.org` is a CONFIRMED phishing/impersonation site (fake
  mega.nz downloads). `simplewall.net` is an unofficial stale SEO portal (separate).
  Official sources only: `henrypp.org` + GitHub Releases — and our signed packs/
  update feed (Phase 1) exist precisely to make this class of confusion harmless.
- Upstream contribution candidate: #2167 fix as an upstream-clean PR (DEC-09
  reputation path; needs porting back to the pristine tree).
