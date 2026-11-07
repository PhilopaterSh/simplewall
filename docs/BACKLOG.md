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

## P1 — composite T003-T006 follow-ups (from the 2026-11-07 goldfish review)

1. **UI-hang risk (S4, real):** `_app_state_deploy/revoke` and
   `_app_publisher_revokepath` hold module-exclusive locks across
   `_wfp_destroyfilters_array`, which SendMessages to the toolbar/statusbar —
   a UI thread blocked on the same lock while the holder messages it = hang.
   Fix: snapshot GUIDs under the lock, destroy outside it, or defer to
   wfp_queue. Do before Phase 1 release.
2. **Held-pending counter coherence (S3):** counter not released on
   Esc-close/editor-dismiss/app-delete/timer-expiry — tray can show stale
   "N held". Release on prompt destroy + revokeapp.
3. **Header/doc mismatch (S5):** composite_state.h "once without context
   falls back to app-wide" is wrong — the code refuses to deploy (correct,
   safe). Fix the doc. Undocumented edge: TpAllocTimer failure leaves a
   2-minute-bounded permit with no timer.
4. Dual-feed double-count: one block can be counted by both the WFP feed
   and the 5157 feed — dedup pass when batch review (T007-era) lands.
5. Session filters vanish on BFE service restart until next rule-apply
   (non-persistent by design, FR-04) — document in user docs.
6. Publisher validation revocation: drop-out on revoked certs requires
   IsOCSPEnabled (default off) — document.

## Identity-research salvage (2026-11-07, adversarial review of the ProcessStartKey proposal)

- **[DONE] UDP PID-reuse path fix**: re-resolve owner path when
  `liCreateTimestamp` changes on a matched (pid, port) row (network.c, udp4+udp6,
  ~12 LOC). The full (PID, ProcessStartKey) + second ETW session proposal was
  REDESIGNED away (adversarial review: 5157/WFP events carry no PID — kernel path
  capture already correct; SI does NOT use Kernel-Process ETW; ProcessStartKey
  needs build-fragile undocumented structs).
- **[P2] 5157 capture-side dedup LRU**: current dedup is a single-slot 2-second
  global window (composite_eventlog.c) — any interleaved event evicts it. Replace
  with a bounded multi-entry LRU of event keys (~40-60 LOC).
- **[P2] AGENTS.md rewrite**: contains unrelated injected text — replace with real
  project conventions (it guides future coding agents).
- **[Phase 3 design note]**: process identity = lazy PID→(ImageName, CreateTime)
  map over the already-vendored `_r_sys_enumprocesses` — NO ProcessStartKey, NO
  second ETW session (carries the adversarial redesign verdict into the Phase 3
  design round).
