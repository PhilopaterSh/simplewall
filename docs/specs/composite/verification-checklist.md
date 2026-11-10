# Interactive verification checklist (owner run, 2026-11-10)

> Covers every fix and gate pending runtime confirmation. Binary:
> `bin\64\simplewall.exe` (current build includes: r1 P1 fixes S4/S5,
> inbound port swap, S3 held-pending counter — commits 215d4af4, 33aedf67,
> db9260c1). Run as admin. Record PASS/FAIL + a one-line note per item;
> update RESUME.md when the run is complete.

## 0. Baseline first (blocking, upstream #2161)

- [ ] 0.1 Install/run the binary; confirm a rule actually blocks: block a
      known app (e.g. ping or a browser), verify it cannot connect, then
      re-allow. If blocking is broken, STOP — everything else is moot.

## 1. S3 held-pending counter (the tournament fix, 6 steps from the judge)

- [ ] 1.1 Enable single-flight (default on); rapidly trigger >=3 novel
        connections from different apps -> tooltip/status shows "N held".
- [ ] 1.2 Press Esc on the prompt -> counter drops to 0 immediately (was:
        stale N until restart).
- [ ] 1.3 Repeat, click Allow-Once -> counter 0 (decide + destroy path).
- [ ] 1.4 With a prompt open and held showing, delete one held app in the
        main window -> its count drops (revokeapp fold path).
- [ ] 1.5 Temporary permit expiry with holds pending -> count drops, tray
        refreshes without restart (timer path).
- [ ] 1.6 Prompt again after 1.2 -> holds re-accumulate only for apps
        throttled during the NEW prompt.

## 2. S4 UI-hang fix (detach-under-lock/destroy-outside)

- [ ] 2.1 Open a prompt, press Esc repeatedly across several prompts — no
        freeze.
- [ ] 2.2 Trigger an "always" decision then immediately delete the app —
        no freeze, app list stays responsive.
- [ ] 2.3 Let a short timer expire while dragging the main window — UI
        stays live during the revoke (timer path no longer destroys
        filters under lock_state).

## 3. Inbound port-swap fix

- [ ] 3.1 Generate an inbound connection event (e.g. an app receiving an
        inbound connection), open the log — local/remote ports must match
        reality (local = machine port for inbound), and the address roles
        must agree with the port roles (remote = peer).

## 4. Upstream regression checks (#2167, #2163)

- [ ] 4.1 Resize storm: drag-resize the main window rapidly for ~10 s —
        no crash (stack-overflow guard).
- [ ] 4.2 Reboot persistence: reboot, verify settings/autostart survive
        and filters re-apply (Win11 26H2 admin-protection check).

## 5. Notification baseline (r6 prerequisite)

- [ ] 5.1 A prompt appears within ~1 s of a novel outbound connection.
- [ ] 5.2 No duplicate prompts for the same app in one session.
- [ ] 5.3 "N held" wording matches reality during a live prompt.

## 6. Uninstall flow

- [ ] 6.1 Uninstall leaves networking fully intact (no DNS breakage, no
        orphan filters — verify with `netsh wfp show filters` cleanup).

## After the run

- PASS all -> owner proceeds: merge PRs #9 -> #11 -> #12, then the r6
  decision (goldfish amendment round agenda now includes the three r6
  gaps from review-external-senior-2026-11-10).
- FAIL any -> record the failing step + observed behavior in RESUME.md
  and file it in docs/BACKLOG.md before any merge.
