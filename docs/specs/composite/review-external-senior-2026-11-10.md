# External senior-practitioner review (2026-11-10)

> Fresh-context independent assessment by a subagent tasked with a ~10-year
> reverse-engineering / network-security / pentest / software-engineering
> perspective. NOT part of the design.md goldfish review series (r1-r4);
> this is an external reality-check of the whole composite effort. Scope:
> is the core sound and deployable in the real world, or untested fantasy?
> Reviewed `design.md` (r5), `design-r6-draft.md`, `spec/plan/tasks`,
> `docs/BACKLOG.md`, `RESUME.md`, `review-r1/r2`, and the implemented
> composite code (`composite_audit.c`, `composite_eventlog.c`,
> `composite_state.c`, integration points in `wfp.c`/`main.c`/`log.c`).
> Recorded verbatim-in-substance by the orchestrating session; triage
> pending owner.

## Verdict

**SOUND-WITH-CONDITIONS** — confidence medium-high. The core (user-mode WFP
per-app filtering, net-event prompting, WFAS-layer Lockdown backstop) is real
engineering on a real engine, and the docs repeatedly refuse overclaims (no
driver, no pre-ALE magic, Lockdown "negatable by any other elevated process").
But the implemented ~2,600 LOC of composite code has demonstrably never
delivered one prompt end-to-end (the 5157 pipeline shipped inert), and the
conditions are the usual fork-killers: empirical testing before release, the
S4 hang fix, no machine-wide audit policy by default, and signing re-key.

## Reality checks

### 1. Threat-model honesty — better than typical, two soft spots

Verified honesty: DEC-02 explicitly rejects kernel/bandwidth-shaping
ambitions; RSK-07 admits Lockdown is negatable by any elevated process; RSK-01
admits the audit subcategory is machine-wide and GPO-revertible; review-r1
finding 5 correctly killed the "signer-hash match condition" idea before
implementation (DEC-05's signer-anchor + materialized-path-filters workaround
is the correct user-mode answer). The #2123 `_LUID` svchost service-SID churn
is honestly logged in `docs/BACKLOG.md` rather than papered over.

Soft spots:
- The BENCH protocol itself flags that loopback net-event collection is
  unverified (`design-r6-draft.md` step 6) — UWP loopback exemptions are a
  classic real-world bypass surface and nobody has run this yet.
- Phase 3 FR-14 ("detect and block apps bypassing the resolver", DoH /
  own-resolver evasion) is asserted as a contract with no mechanism. Expect
  app-embedded DoH to walk straight past a user-space resolver-ownership
  layer. Mark it aspirational, not contractual.

Raw sockets and pre-ALE traffic are implicitly out of scope by DEC-02 —
correctly stated.

### 2. r6 dual transport — engineering-sound, three concrete gaps

The inversion (net-event primary, 5157 fallback) is the right call: it kills
the machine-wide-audit default, and the attribution design (providerKey
verdict + wholesale cache invalidation on apply) is correct — the
filterId→filter→provider chain exists at `src/log.c:655-722`, and the storm
class (#2114) is killed structurally, not throttled. The r2 round's two
corrected API facts (no `subLayerId` field in net-event structs; no
type-scoping in the enum template) show the API surface is being checked
against the SDK.

Gaps the draft misses:
1. **Fallback latency window:** tamper-off of `COLLECT_NET_EVENTS` leaves
   prompts dead for up to one 60 s heartbeat beat before the tray flips. The
   draft never states this window or offers a fast-path probe on
   subscription-error delivery.
2. **Net-event queue overflow under flood:** BFE net-event delivery has
   finite buffering; under #1807-style floods drops are likely (inferred,
   not verified). BENCH step 7 tests UI responsiveness, not event
   completeness — the test should assert an expected event count.
3. **5157 fallback inherits Security-channel pathologies:** log wrap under
   Lockdown is acknowledged (RSK-08), but `EvtSubscribeToFutureEvents`
   push-mode callbacks run on the event-log service's thread — slow parsing
   there can throttle or error out. The current single-slot dedup
   (`src/composite_eventlog.c:414-425`, verified) makes any flood a prompt
   storm until T017's LRU lands.

Service-account ACLs on the Security channel are moot as primary (the app
runs elevated as the user).

### 3. Codebase reality — competent code, spec-ahead-of-runtime culture

Verified in code: `composite_audit.c` is genuinely defensive —
corrupt-inventory refuse-to-proceed (:325-332), inventory-before-any-machine-
write (:336-371), inventory deleted only after both restores verifiably
succeed (:485-492), BOOLEAN-API/GetLastError mapping documented (:9-11).
`composite_state.c` implements the hardening tri-state transaction contract
and refuses to upgrade a contextless "once" decision to app-wide (:148-149).

The counter-evidence: two adversarial rounds found the pipeline inert as
shipped (config keys read at `wfp.c:2189`, `main.c:3692`, written nowhere), a
confirmed UI hang (S4, `composite_state.c:75-76` holding `lock_state` across
`_wfp_destroyfilters_array`, which SendMessages the window), an inbound port
swap (`composite_eventlog.c:350-353`), and a session re-prompt loop. Pattern:
implementation lands, empirical runtime verification does not. RESUME.md
explicitly leaves interactive verification of the binary pending on the
owner.

For a solo maintainer the killer is not the C — it is the surface: 24 tasks,
3 phases, a packs repo with CI, monthly upstream rebases, and a no-CI repo
(OPS-01 admits "local pre-merge otherwise"). Governance mitigates
(fork-namespaced files, DEC-09 pull-not-duplicate); the arithmetic still
doesn't.

### 4. Security hardening — sound design, void signing story

DACL hardening and the anti-rollback watermark design (`pack_watermarks.json`
outside the rebuild set, corrupt ⇒ refuse, not reset) are the right shapes;
the audit-inventory user-writable-DACL hole is known and fix-scheduled
(r6 §3.6). But the PFX password is public in pushed history (commit
bfe26cc3) — until re-keyed, every Authenticode and signed-pack claim is
discreditable by anyone who reads the repo, and the confirmed #1954
phishing site means impersonation risk is live. GPG-only interim is honestly
flagged as not building SmartScreen reputation (RSK-03). Signed packs remain
sound *after* a fresh key; before that, they are theater.

### 5. Performance/stability — features and stability genuinely pull

The fork carries the #2167 stack-overflow fix; upstream's top complaints are
memory growth (#2135) and hangs under flood (#1807). Composite adds
per-event WinVerifyTrust on the BFE delivery thread (cache + 30 s rate-limit
planned, r6 §3.3 — the mitigation is right), a heartbeat thread, a ledger
diff loop (Phase 2), and an ETW DNS session (Phase 3) — all on one
single-binary, no-CI codebase. The NFR budgets / unfiltered-window metric /
bench step 7 answer is the most honest version of this tension seen in a
hobby fork, but every added hook is another re-entrancy candidate in a
codebase whose one shipped crash was exactly that class.

## The killer list (ranked)

1. **Never run end-to-end.** Pipeline shipped inert; interactive verification
   pending. Mitigation: make the 7-step BENCH exit-0 a merge gate; run it
   this week.
2. **S4 deadlock class.** Mitigation: T023 snapshot-under-lock fix before any
   Phase 1 release (already scheduled — keep it scheduled).
3. **Leaked signing material.** Mitigation: new cert + new pack key; treat
   old material as burned; rotate before first public release.
4. **Machine-wide audit policy distrust.** Mitigation: opt-in only, never
   default-on; document AV-visibility risk in the settings tooltip.
5. **Solo-maintainer scope arithmetic.** Mitigation: ship Phase 1 only;
   hard-freeze Phase 2/3 until real users + clean soak.

## What is genuinely good

- Adversarial review culture that actually catches things (r1 finding 5, the
  r6 API corrections, the inert-pipeline and S4 discoveries).
- Upstream-issue mining with file:line anchors (#2123, #2161, #1954).
- Honest verification split; loopback marked UNVERIFIED in BENCH.
- Licensing hygiene verified to the API level (DEC-07, GPL-3.0 vs AGPL
  distinction actually checked).
- Defensive code discipline in `composite_audit.c`/`composite_state.c`:
  refuse-on-uncertainty, exact-revert-only, documented lock nesting.

## Triage (owner, pending)

Each finding needs an accepted / rejected-with-rationale / unresolved entry
recorded in `tasks.md` per the goldfish-gate convention. Suggested immediate
actions: fold killer-1 into the pending owner verification round; add the
three r6 gaps (§2) to the r6 goldfish amendment round agenda; mark FR-14
aspirational in the next design revision.
