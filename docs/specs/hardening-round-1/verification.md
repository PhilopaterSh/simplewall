# Verification: Hardening Round 1 (Trust-Boundary Fixes)

Task T015 (RSK-00): manual verification procedures for the checks that
cannot be automated without a BFE failure-injection harness. Automated
smoke tests live in `tools/hardening-smoke-tests.ps1` (task T014).

Run everything from the built fork (Release) on a clean VM snapshot.

## FR-01 / OPS-01 — degraded-enforcement state (manual, RSK-00)

Triggering a real `FwpmFilterAdd0` failure for a vital global filter needs
a fault-injection harness; this round accepts a contract review:

1. Code review: every `_wfp_createfilter` call inside
   `_wfp_createglobalfilters` goes through `_wfp_createvitalfilter` and its
   non-success status marks the degraded flag; `_wfp_installfilters` resets
   the flag at entry and logs one aggregated entry on exit.
2. Forced-path check (debug only): temporarily invert a status check in
   `_wfp_createvitalfilter`, build, apply rules, and confirm:
   - the status bar shows the degraded message,
   - the tray tooltip shows `(enforcement degraded)`,
   - the log view has exactly one `vital filters failed to install
     (enforcement degraded)` entry,
   - reverting the injection and re-applying clears the state.
3. Restore the code, rebuild.

## FR-02 — transaction tri-state contract (manual, RSK-00)

1. Code review checklist:
   - `_wfp_transact_start` returns `TXN_STARTED / TXN_IN_PROGRESS /
     TXN_FAILED` and never conflates them;
   - every non-owned outcome releases the shared `lock_transaction`
     acquisition the site made;
   - `TXN_FAILED` never reaches `FwpmTransactionCommit0`; abort paths
     dereference their local arrays before returning;
   - outer sites (`_wfp_initialize`, `_wfp_installfilters`,
     `_wfp_destroyfilters*`) map `== TXN_STARTED` to their boolean.
2. Behavioral spot-check: with `FwpmTransactionBegin0` forced to fail
   (debug injection), apply rules twice, then confirm the UI is not stuck
   in "applying" state (`_wfp_isfiltersapplying` no longer sticks).

## FR-04 — de-elevated log viewer (manual)

1. Set `LogViewer` (settings) to any unsigned editor (e.g. Notepad2).
2. Open the log (menu). In Process Explorer: the editor process must show
   Medium integrity (not High), parented under the shell, not simplewall.
3. Negative path: rename/close Explorer-related failure is hard to force;
   accept the logged refusal path by temporarily blocking
   `CoCreateInstance` of CLSID_Shell in a debug build — the log must
   contain the refusal and no process may start.

## FR-05 / SEC-04 — privilege minimization (manual)

1. Idle check: while simplewall runs elevated and idle, open its process
   in Process Explorer → Security tab → privileges must NOT list
   SeDebugPrivilege, SeSecurityPrivilege, SeTakeOwnershipPrivilege,
   SeBackupPrivilege, SeRestorePrivilege; SeIncreaseBasePriorityPrivilege
   IS present.
2. Kill-window check: click Kill on a notification while watching the
   privilege list: SeDebugPrivilege may appear transiently and must be
   gone afterwards.

## FR-06 / DATA-01 — wufix ImagePath preservation (manual)

1. Note current `HKLM\SYSTEM\CurrentControlSet\Services\wuauserv\ImagePath`.
2. Enable WU-fix in settings → ImagePath becomes
   `%systemroot%\system32\wusvc.exe ...` and a new `ImagePathOriginal`
   value equals the original.
3. Disable WU-fix → ImagePath equals the original; `ImagePathOriginal` is
   deleted.
4. Re-enable, hand-edit ImagePath to a fake service path, disable →
   the hand-edited value must NOT be "restored over" (only values that
   are still ours are restored).

## FR-09 / SEC-06 — log file ACL (manual)

1. Enable logging; find the log file (settings → log path).
2. `icacls <logfile>`: must list only the current user, Administrators and
   SYSTEM with full control; no Users/Everyone entries.
3. Migration: create a log file with an older build (or strip the ACL),
   then start the new build — the ACL must be corrected at startup.

## NFR-01 — zero UX regression (manual pass)

Enable/disable, apply rules, open log, show notifications, kill a process
from a notification, toggle rules, edit a rule, change settings, exit —
no visible behavior change vs upstream except the documented degraded
state.

## NFR-02 — build gate (environment-blocked here, run on owner machine)

The `routine` submodule and MSVC are not available in the authoring
environment, so T016 stays open until run on the owner's machine:

1. `git clone https://github.com/henrypp/routine ..\routine` (sibling of
   the repo; `..\builder` only needed for rules repacking).
2. Open `simplewall.sln` (VS 2022, Win10/11 SDK), select Release | x64.
3. Add `/analyze` to compiler options (or build with the provided
   configuration) — expect zero new warnings at `/W4` on the touched
   files: wfp.c, controls.c, profile.c, main.c, log.c, log.h, messages.c,
   notifications.c, helper.c, db.h, wfp.h.

## NFR-03 — no rule-apply latency regression (spot check)

Toggle a rule 20 times and compare perceived apply latency against an
upstream build; the privilege helper runs only on the kill path, not on
apply.
