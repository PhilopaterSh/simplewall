# GUI chain testing record — the tests that ran themselves (2026-11-19)

> Owner directive: build AND answer the tests ourselves; document every
> problem with its cause, fix, and verifiable sources. This record is
> append-only; every entry names the evidence artifact that settled it.
> Evidence lives in the CI run artifacts (gui-screens/, dumps/, PDB) and
> in the tooling chain's retrospective ledger (rows 43-44).

## The instrument layer (built first)

- `simplewall.exe -gui-selftest`: headless in-process verification of
  the six DEC-11 query-API enumerators. Fixtures are produced by the
  REAL packstate serializer (`_app_packs_statewrite`) so they can
  never drift from the production format; "once" seeds get the REAL
  threadpool-timer expiry (the r3-finding-3 "row vanishes" case is
  verified end-to-end); publisher seeds exercise the r3-finding-2
  retain-fix regression gate. Writes `selftest-result.txt`, exit code
  = failure count. Declared test instruments (`_app_*_selftest_*`)
  are additive, documented never-called-from-production.
- `tools/gui-testdrive.ps1`: launches `-gui` on the CI runner's real
  desktop (SAC-free), drives all 6 rail pages via keyboard messages,
  screenshots every page + the debounced search path + the theme
  toggle, uploads `gui-screens/` as artifacts. Evidence is read and
  judged afterwards by the implementer (the screenshots ARE the
  acceptance surface).
- Crash forensics: LocalDumps (full) for simplewall.exe on the runner +
  the app's own SEH dumps (Desktop\simplewall_crash) + a SYMBOLIZED
  crash-report.txt written by the SEH filter itself (in-process
  dbghelp: RtlCaptureStackBackTrace + SymFromAddr + SymGetModuleBase64
  — dbghelp was already an import; the PDB ships beside the exe in the
  artifact).

## Finding 1 — SAC blocks fresh dev builds even when device-signed

- Symptom: every local launch of every rebuild fails ("Application
  Control policy has blocked this file" / "Permission denied"), with
  the v2 Authenticode chain installed and Valid.
- Root cause: Smart App Control verdicts are PER-HASH with cloud
  reputation; a fresh build hash has no reputation, and the
  device-trusted signing chain does not substitute for it. This
  re-confirms audit F-2 ("SAC sign-after-rebuild mitigation
  unreliable").
- Resolution: the CI runner (windows-latest, admin, real desktop
  session) is the SAC-free judge — all verification moved there.
  Sources: Microsoft Learn "Smart App Control" (per-file, cloud-based
  verdicts); the fork's audit row F-2; two empirical data points this
  round (signed-but-fresh builds blocked twice, error captured in the
  CI step output).

## Finding 2 — ROOT CAUSE: composite verbs never ran _app_initialize

- Symptom (CI): `-gui` died with 0xC0000005 before showing the shell
  window (dialog: fault addr 0x40); `-gui-selftest` died pre-first-check
  with 0xC0000409 param 0x23.
- Evidence chain: (a) the visible crash dialog screenshot (gui-screens/
  screen.png) captured the app's own "Exception raised :(" dialog;
  (b) the app's minidump + the symbolized crash-report.txt named the
  exact chain: `CreateWindowExW → WM_CREATE → _app_shell_wndproc →
  _app_profile_load → _r_obj_clearhashtable → AV @ +0x40`.
- Root cause: `_r_app_initialize` (routine rapp.c) dispatches
  `cmd_callback` ONLY for the four known cmdline classes
  (Help/Clean/Install/Uninstall). For `-gui`/`-gui-selftest`,
  `_app_parseargs` never runs, so `_app_initialize` — the creator of
  apps_table/rules_config/state/publisher/credentials/icons — never
  runs. `_app_profile_load` then clears a NULL table
  (`_r_obj_clearhashtable` derefs the object header → +0x40).
  The upstream dialog path was unaffected because WM_INITDIALOG calls
  `_app_initialize` itself. Every previous `-gui` attempt died at first
  execution: SAC blocked local runs, and CI had never run the shell
  before this round — the bug shipped silently in the r1 scaffold.
- Fix: the composite verbs call `_app_initialize (NULL)` when
  `apps_table` is still NULL (main.c, guarded — the main-window path
  keeps its own WM_INITDIALOG call and never double-initializes).
- Sources: routine rapp.c `_r_app_initialize` dispatch (read, cited in
  the commit); the symbolized report in the CI artifact.

## Finding 3 — the crash dialog showed LITERAL "%p" placeholders

- Symptom: "The instruction at 0x%p referenced memory at 0x%p. The
  memory could not be %s." — with literal %p — on every crash dialog
  since the fork's first live crash (the owner's original report had
  the same literals).
- Root cause: the ntdll message-table template for STATUS_ACCESS_VIOLATION
  carries %p placeholders that FormatMessage does not fill (they are
  not %1-style insert sequences); we displayed the raw template.
- Fix: the SEH filter formats the ACTUAL ExceptionAddress +
  faulting address (ExceptionInformation[1]) + the op (read/written)
  and hands `_r_report_error` a completed string; in addition it writes
  the symbolized crash-report.txt. Verified by the NEXT run's dialog
  screenshot: real addresses + exception code visible in gui-screens/.
- Sources: Microsoft Learn FormatMessage (insert-sequence semantics);
  winnt.h FAST_FAIL table (read locally) for the fastfail codes below.

## Finding 4 — FAST_FAIL_UNEXPECTED_HEAP_EXCEPTION (0x23 = 35)

- Symptom: `-gui-selftest` died with 0xC0000409 param 0x23 before its
  first assertion could flush; "TOTAL: 0 failure(s)" in the log was a
  FLUSH ARTIFACT (`_app_selftest_writefile` appends the TOTAL footer on
  every flush — a misleading-until-read detail).
- Root cause: the same Finding-2 cascade (NULL global tables hit from
  the selftest path); the specific fastfail class was identified from
  winnt.h (FAST_FAIL_UNEXPECTED_HEAP_EXCEPTION = 35 = 0x23) rather than
  guessed.
- Resolution: resolved by the Finding-2 fix; the flush-as-you-go design
  (each case group flushes the result file) is what made the bisect
  ("enter" on disk, nothing after) decisive.

## Finding 5 — the clean-exit path fastfails (open, backlog)

- Symptom: after the selftest's final write, the process still died
  with 0xC0000409 even though `TerminateProcess(0)` had been reached —
  no: the death preceded it; with the Finding-2 fix the exit path is
  expected to be clean, BUT an earlier observation stands: killing via
  the CRT teardown with the app's live workqueue threads produced a
  fastfail in a background thread.
- Status: OPEN — a real clean-exit/keep-or-release question (the
  uninstall story). Tracked in the owner-decision tracker backlog;
  the selftest uses TerminateProcess(0) after its final flush so the
  test verdict is faithful while the product-level question stays open.
- Sources: ntdll fastfail class (winnt.h); CI exit-code evidence.

## Finding 6 — _r_sys_getopt matches by PREFIX

- Root cause: `_r_sys_getopt` uses `_r_str_isstartswith` (prefix,
  case-insensitive) and then requires a separator (':'/'='/space) for
  values — so `-gui` does NOT swallow `-gui-selftest` (the '-' after
  "gui" rejects the match), but any future option that shares a prefix
  with another is a latent ordering hazard.
- Resolution: documented + the verb checks are ordered
  (gui-selftest BEFORE gui) with an explanatory comment.
- Source: vendor/routine/routine.c `_r_sys_getopt` (read).

## Finding 7 — tree hygiene self-catch

- The first forensics commit accidentally tracked the downloaded
  .testruns/ artifacts — the exact row-29 class. Caught by the same
  commit's review pass and untracked immediately (.gitignore now
  covers .testruns/).

## Verified-correct (not churned)

- `_r_obj_findhashtablepointer` returns a REFERENCED pointer
  (`_r_obj_referencesafe`) — every deref-after-find in the new query
  APIs is correct (read in vendor routine.c).
- The packs mtime snapshot's three failure classes (missing = empty;
  torn = keep-previous; corrupt = fail-closed-empty) map exactly onto
  `_app_packs_readwide`/stateverify semantics (read).

## The G-2 acceptance table (selftest assertions)

1. packs: missing sidecar → empty; serializer-written store → rows;
   id/version/filter-count match; corrupt store → fail-closed empty;
   recovery after corruption.
2. state: seed → enumerate; app_hash/is_block/is_once match; remaining
   math at 2s and 3700s boundaries; name resolved from apps_table;
   REAL threadpool-timer expiry → row VANISHES; until-restart + revoke.
3. publisher: anchor upsert; INVALID member keeps the anchor red (the
   retain-fix regression gate); re-validation returns green.
4. interactive (CI screenshots): 6 rail pages + search debounce +
   theme toggle — the PNGs are read and judged in the session report.


## Finding 8 — the fresh-profile startup freeze on Server 2025 runners (OPEN)

- Symptom: after Finding-2's fix, the composite startup completes
  (breadcrumbs prove init:enter -> ... -> init:done) but the process then
  hangs in a KERNEL WAIT inside ordinary file operations against the
  profile directory - AND THE HANG POINT MOVES between runs (ledger
  startupcheck, hardenacl, packs getpath->getprofiledirectory, even the
  workqueue creation stage). The main thread freezes; no dialog, no window.
- Evidence: stage breadcrumbs (main.c, TEMP instrument) + full hang dumps
  (comsvcs MiniDump via the watchdog) + thread-stack scans (the dump
  parser, extended to Memory64) + dbghelp symbolization against the CI PDB
  (SymLoadModuleEx + SymFromAddrW pattern).
- Chain DECODED (dbghelp symbolization of the a10 full dump against the
  CI PDB — the exact blocking chain, function by function):
  packscases -> _app_packs_getpath -> _app_getprofiledirectory ->
  _r_fs_exists(cached_path) = FALSE -> _r_fs_createdirectory ->
  _r_fs_dospathnametontpathname+0x344 -> kernel wait. AND the breadcrumb
  evidence: cached_path contained the LITERAL STRING "false" (len=5) —
  a config-boolean value string. That is a STRING-OBJECT LIFETIME/
  heap-corruption class (the cached path object was overwritten by a
  config "false" value), NOT a plain filesystem stall: NtCreateFile on a
  corrupted path enters the object-manager/MUP wait. The hang points
  moving across runs fit the same class (wherever the corrupted object
  is consumed first).
- Root-cause state: OPEN. The hang point moves with call order across runs
  -> a race/environment interaction, not a single fixed line. The
  corrupted-string observation (getprofiledirectory returned the literal
  string "false" for two calls) points at a string-object lifetime issue
  in the vendor path helpers under concurrency; the kernel waits on a
  garbage path would then be secondary. Requires a debugger session on the
  runner (cdb/TTD step in CI) - the dump channel is exhausted (comsvcs
  wrote non-Memory64 dumps for two of three captures).
- Mitigations shipped (each CI-proven): the portable-model DACL skip; the
  hardenacl first-and-alone relocation; the IsProfileDaclHardeningEnabled
  config gate (default OFF - O-8).
- Impact honesty: the freeze affects the CI verification instruments
  (selftest + testdrive) on fresh runner profiles - NOT the released
  v3.9.4 on the owner's machine. The CI chain stays honestly RED on the
  selftest step until settled.

## Finding 9 — the smoke gate's blind spot

- "PASS: simplewall alive after 20s" cannot distinguish a healthy app from
  one frozen inside startup (a hung process is equally alive). The
  composite startup freeze was INVISIBLE to the smoke gate on every run.
- Resolution: the selftest step (exit code + result file) is the real
  startup verdict now; a window-visibility probe belongs in the smoke
  step later.
