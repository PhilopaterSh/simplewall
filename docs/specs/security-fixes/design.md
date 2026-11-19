# Design: Security Fixes — the 2026-11-17 full-scope audit remediation

> Status: DRAFT, NOT approved. The gate stays red until a human records the
> approval here (revision + approver). Nothing downstream is generated
> before that.

> Revision `2026-11-17-r2` — goldfish review of r1: **VERDICT APPROVE-WITH-CHANGES**
> (2 MAJOR normative corrections + 6 MINOR — all integrated below; key review evidence:
> `_r_sys_runasadmin` = ShellExecuteExW WITHOUT SEE_MASK_NOCLOSEPROCESS, returns at spawn;
> `IDM_OPENRULESEDITOR` is a context-menu command with NO control — the gate uses the FR-07
> proxy control `IDC_ALLOW_BTN` per notifications.c:1664; the fix also closes a SECOND hole:
> the download error path leaves a stale-partial file at cache_path which today would be
> elevated-executed). Owner directive recorded verbatim (2026-11-17):
> (2026-11-17):** «اكمل العمل عليها من فضلك بالشكل الصحيح واعمل بالخطة
> وبالشكل المناسب goldfish-gate» — commissioned as the remediation of the
> owner-commissioned 3-agent full-scope audit (agent-1 product security:
> VERDICT SOUND-WITH-GAPS, ledger rows 31/25-26; every finding re-verified
> present on merged master by the cross-reference agent). Scope = the three
> MAJOR findings + one documentation fix. Everything else from the audit
> (minors, NFR-02 /W4+/analyze gate) routes to BACKLOG, not this chain.

> Revision `2026-11-19-r3` — **FIX-5 ADDED: the _r_fs_setpos ABI sweep** (live crash
> evidence: 8 dumps from the composite lane scratch build ALL crashing at
> `_r_fs_setpos+0x23` with a NULL-pointer READ, symbolicated via the mergetest
> map). Root cause: the vendored signature is `_r_fs_setpos (HANDLE,
> PLARGE_INTEGER)` but FOUR rapp.c callers pass the scalar `0` (rapp.c:2214,
> 2240 in `_r_update_downloadupdate` — a ROUND-2 era miss: the DEC-04 ABI sweep
> covered createfile/setprocessprivilege/reg_queryvalue/renamefilebyhandle but
> NOT setpos/setsize; and rapp.c:3207/3231 in FIX-1's own T001 implementation
> — the owner's mergetest build inherited both). The correct pointer-call
> idiom already exists in the same file (rapp.c:3305, log.c:146). v3.9.3 is
> affected on every language-download verify and every install; re-release
> (v3.9.4) owed. Goldfish delta review per the tiered-review protocol.

## Problem and intended outcomes

The 2026-11-17 full-scope audit (fresh-context, file:line-evidenced, claim
table 25+ rows all-real) found three MAJOR gaps in the merged product — two
of them in security-critical paths (the elevated installer and the
accountability hardening), one contradicting a hardening-round-1 claim:

1. **MAJOR-1 — updater install-window TOCTOU** (`vendor/routine/rapp.c`
   `_r_update_install` ~3139-3163): the cached installer is executed
   **elevated** after only an existence check. Verification (sha256) happens
   once at download time and the exclusive handle is closed there; the file
   sits in a user-writable cache dir. A same-user process can swap the
   verified installer between the user's "install now" click and the
   elevated execution → arbitrary code execution elevated. **The released
   v3.9.2-hardened.1 exe carries this** — re-release owed after the fix.
2. **MAJOR-2 — FR-12 config-dir ACL runtime-broken** (`src/composite_integrity.c`,
   wired `src/main.c:1896`): (a) the `SetEntriesInAclW` result (a PACL) is
   passed to `GetSecurityDescriptorDacl`, which expects a self-relative
   SECURITY_DESCRIPTOR — type confusion → garbage/`STATUS_INVALID_PARAMETER`,
   hardening silently never applies (failures logged non-fatally per NFR-01);
   (b) no interactive-user ACE exists (contradicting the module header);
   (c) `DACL_SECURITY_INFORMATION` without the PROTECTED flag lets inherited
   user-writable ACEs survive. Net effect: the accountability sidecars
   (audit ledger, pack watermarks, lockdown snapshot) are NOT tamper-resistant.
3. **MAJOR-3 — ungated notification PERMIT-rule mint** (`src/notifications.c`
   `IDM_OPENRULESEDITOR` 1883-1947): the branch mints a `FWP_ACTION_PERMIT`
   rule, installs it to WFP immediately (`_app_ruleenable(ptr_rule, TRUE,
   TRUE)`), and persists it — with no `_r_ctrl_isenabled` safety gate,
   contradicting hardening-round-1's "every action-bearing branch is gated"
   (design.md:75). Upstream-inherited; every sibling branch IS gated.
4. **DOC — stale endianness comment** (`src/update_key.h:6-7`): claims the
   CNG blob "converts to little-endian" — the r4 reconciliation proved the
   opposite (verbatim big-endian, tools/cng-signature-bench.py) and one such
   stale comment already caused a regression. Documentation-only.

Intended outcomes:

- The verify→execute window of the updater is closed: writers are excluded
  by share-mode for the whole window and the hash is re-verified on the held
  handle immediately before elevated execution; a hashless manifest refuses
  to install (fail-closed, closing audit finding 4).
- The composite config-dir ACL applies the intended policy (Administrators
  FULL, SYSTEM FULL, interactive user READ) as a PROTECTED DACL, correctly
  (no type confusion), non-fatally, and is verified at runtime by the
  existing startup check.
- Every action-bearing notification branch is gated identically; refusals
  are rate-limited-logged.
- The endianness documentation matches the bench-proven convention.

## In scope and out of scope

In scope:

- FIX-1: `_r_update_install` hardening in `vendor/routine/rapp.c` (open →
  verify → hold → execute → close), installer-component hash requirement.
- FIX-2: `src/composite_integrity.c` DACL rewrite (correct PACL plumbing —
  pass the SetEntriesInAclW result DIRECTLY to SetNamedSecurityInfoW's pDacl
  parameter; the GetSecurityDescriptorDacl round-trip is deleted — three-ACE
  policy per DEC-03 with the user SID pinned to the PROCESS-TOKEN user (not the
  Interactive group — shared-host widening), PROTECTED flag) — non-fatal
  semantics preserved (NFR-01). Review precision: the "non-elevated session
  logs ACCESS_DENIED" journey text is DEAD (APP_NO_GUEST in all configs — a
  non-elevated instance exits before hardening; fix the main.c:1885 comment
  during implementation); the SYSTEM-ACE mismatch (code grants READ|EXECUTE,
  DEC-03 says FULL) is part of the rewrite; the declined-UAC path attempts a
  debug-log write in the profile dir that fails silently once hardened —
  documented, non-fatal.
- FIX-3: safety gate + refuse-log on the `IDM_OPENRULESEDITOR` branch in
  `src/notifications.c` (mirroring the sibling-branch gate pattern).
- FIX-4: `src/update_key.h` comment correction (BIG-endian verbatim; bench
  reference).
- FIX-5 (r3): the `_r_fs_setpos` ABI sweep — all four scalar callers in
  `vendor/routine/rapp.c` (2214/2240 download-verify, 3207/3231 install-verify)
  pass a zeroed LARGE_INTEGER by pointer, matching the vendored PLARGE_INTEGER
  contract (log.c:146 + rapp.c:3305 idiom).
- Chain docs under `docs/specs/security-fixes/`.
- **BACKLOG routing deliverable** (review MINOR-8): append the six routed
  audit minors to `docs/BACKLOG.md` (hashless FILE manifests, log-DACL
  PROTECTED flag, /W4+/analyze gate, WM_DROPFILES, _r_update_navigate icon
  misuse, editor-cancel-does-not-undo) + record the audit evidence location:
  `docs/specs/tooling/retrospective-ledger.md` rows 31-38.

Out of scope (prohibited adjacent work):

- The audit's MINOR/INFO findings (hashless FILE-component manifests, log
  DACL PROTECTED flag, /W4+/analyze NFR gate, WM_DROPFILES surface,
  `_r_update_navigate` icon misuse, bin/mergetest removal) — route to
  `docs/BACKLOG.md`, not this chain.
- The PFX re-key (owner-gated, O-1) and the re-release mechanics (G-3) —
  this chain only produces the fixed, gated, signed-when-released code.
- Any change to the feed format, the C tool suite, or the composite
  Phase 2/3 modules beyond `composite_integrity.c`.
- The parallel session's `src/gui/` work (untouched; different lane).

## User journeys and behavior

- FIX-1 journey: user clicks "install now" → the app opens the cached
  installer with GENERIC_READ + share(READ|DELETE) — a concurrent writer
  now gets a sharing violation for the whole window → the held handle is
  hash-re-verified against the signed manifest's pin → on mismatch the
  install is refused and logged fail-closed (and the artifact deleted) →
  on match the elevated install runs while the handle is held → handle
  closed after. A manifest without a hash for an INSTALLER component
  refuses to install (logged).
- FIX-2 journey: startup hardening builds the three-ACE DACL (Administrators
  FULL, SYSTEM FULL, interactive user READ) and applies it PROTECTED to the
  profile directory; non-elevated sessions log ACCESS_DENIED and continue
  (NFR-01 preserved); a same-user tamper attempt on the composite sidecars
  now requires elevation.
- FIX-3 journey: a `WM_COMMAND` `IDM_OPENRULESEDITOR` arriving while the
  notification action buttons are disabled (the 900 ms safety window) is
  refused and rate-limited-logged — identical to the ALLOW/BLOCK/KILL
  branches' behavior.
- FIX-4: no runtime behavior — comment corrected to the bench-proven
  BIG-endian verbatim convention.

## Constraints and quality attributes

- NFR-01 (preserved): hardening failures are never fatal to startup — but
  every failure is logged with its exact API name.
- SEC-01: FIX-1 verification is fail-closed (missing hash / mismatch /
  reparse / open-failure all refuse and delete the artifact).
- SEC-05 (untouched): no new processes; the fix holds a handle, it does not
  spawn helpers.
- Performance: the added verification is one SHA-256 over the cached
  installer (~1 MB) — negligible.
- Vendor-lane rule (RSK-05): FIX-1 is a minimal single-function diff in
  `vendor/routine/rapp.c`, sequenced against the current vendor state
  (last vendor commit 999a9294, owner lane).

## Approved decisions

- DEC-01 (S-1): install-window closure by **write-excluding share mode** (open
  GENERIC_READ, share = FILE_SHARE_READ|FILE_SHARE_DELETE — writers blocked,
  the OS loader unaffected) + in-handle re-verification + **hold until
  `ShellExecuteExW` returns** (review: `_r_sys_runasadmin` uses ShellExecuteExW
  WITHOUT SEE_MASK_NOCLOSEPROCESS — it returns at spawn; sufficiency: our handle
  spans the entire blocking call including the UAC consent wait, and after spawn
  the elevated image section keeps writers excluded for the process lifetime via
  the loader handle). Chosen over copy-to-protected-location (adds a second
  artifact lifecycle) and over post-mapping assumptions (fragile). NOT
  "exclusive" — share 0 would break the loader image-open and fail every
  install (review MAJOR-5).
- DEC-02 (S-2): installer-component hash is REQUIRED for the install step
  (fail-closed) — closes audit finding 4 for the dangerous path; FILE
  components keep optional-hash download semantics.
- DEC-03 (S-3): FR-12 DACL policy = the module header's stated intent
  (Administrators FULL, SYSTEM FULL, interactive user READ), PROTECTED flag,
  applied to the profile directory — safe because the app requires elevation
  (rapp.c runasadmin gate) for all config writes; non-fatal on failure.
- DEC-04 (S-4): FIX-3 mirrors the FR-07 precedent EXACTLY: gate on the proxy
  control `_r_ctrl_isenabled (hwnd, IDC_ALLOW_BTN)` (notifications.c:1664 —
  the review: `IDM_OPENRULESEDITOR` is a context-menu command with no control;
  gating on it directly would refuse every legitimate click), rate-limited
  ignore — no new gate mechanism invented. Mechanism note (review): the mint
  activates via the standard apply path (`_app_ruleenable` = is_enable +
  is_createconfig, NOT a direct WFP call); editor-cancel does NOT undo the
  mint (upstream behavior c21b5a14 2021-03-08, intentional quick-allow UX;
  cancel-does-not-undo goes to BACKLOG, outside this fence).
- DEC-05 (S-5): FIX-4 is documentation-only; the CNG bench remains the
  arbiter of the convention.
- DEC-06 (S-6): this chain does NOT touch `src/gui/`, the composite modules
  beyond `composite_integrity.c`, or the feed format.
- DEC-7 (r3): FIX-5 is the DEC-04 ABI-alignment class applied mechanically:
  every `_r_fs_setpos` caller is swept by grep against the vendored signature;
  `_r_fs_setsize` callers verified clean (single caller, correct form). The
  sweep becomes the standing ABI-check for every future vendor call site.

## Risks and open questions

- RSK-01: FIX-1 share-mode change could break the elevated installer's own
  file access. Gate (review-corrected attribution): it is the OS
  loader/CreateProcess that opens the image (read/execute, share
  READ|DELETE) — compatible with our handle; NSIS copies itself to $TEMP
  (reads the original — allowed; writes a new file — unaffected) and
  delete/rename of the original is permitted by FILE_SHARE_DELETE; no
  deadlock (the lock is file-scoped and nothing writes the cached installer).
  The CI launch test + a manual NSIS install round close this before
  re-release. Endpoint: hold spans the blocking ShellExecuteEx call (DEC-01).
- RSK-02: FIX-2 breaks non-elevated config writes IF a session ever runs
  non-elevated (simplewall self-elevates at startup; the non-elevated
  instance is the relauncher). Gate (review-verified): the relauncher exits
  at rapp.c:261-269 via RtlExitUserProcess BEFORE _app_profile_initialize —
  it never writes config; the ONE exception is the declined-UAC debug-log
  write (rapp.c:266 -> _r_log -> profile debug.log) which fails silently once
  hardened — non-fatal, documented. If a real violation appears, the fix
  downgrades to sidecar-directory scope.
- RSK-03: FIX-3 may refuse a legitimate user click arriving in the disabled
  window. Gate: the buttons are disabled for exactly the safety window; the
  gate checks the SAME condition the click-handler path already enforces for
  sibling branches — behavior parity, no new refusal class.
- Open question (owner): publish the fixed build as v3.9.3 immediately after
  gates, or hold for the PFX re-key (O-1) to also land in the same release.

## Traceability Key

| Key | Meaning |
| --- | --- |
| FR-01 | The updater verifies the cached installer's sha256 on a handle opened with a WRITE-EXCLUDING share mode immediately before elevated execution (hold spans the whole blocking ShellExecuteEx call; after spawn the image section keeps writers excluded); any failure refuses and deletes the artifact |
| FR-02 | Installer-component installs refuse (fail-closed, logged) when the signed manifest provides no hash |
| FR-03 | The composite config-dir DACL = Administrators FULL + SYSTEM FULL + interactive user READ, applied PROTECTED, correct PACL plumbing, non-fatal failures |
| FR-04 | The `IDM_OPENRULESEDITOR` notification branch is gated on the FR-07 proxy control (`IDC_ALLOW_BTN`, notifications.c:1664), with rate-limited refusal logging |
| FR-05 | `src/update_key.h` documentation matches the bench-proven BIG-endian verbatim convention |
| NFR-01 | Hardening failures remain non-fatal to startup, exact-API-name logged |
| SEC-01 | Every new failure path fails closed (refuse + log + cleanup) |
| DEC-01 | Share-mode exclusion + in-handle re-verification + hold-through-exec |
| DEC-02 | Installer-component hash required for install |
| DEC-03 | FR-12 policy per module header intent, PROTECTED, elevation-dependent documented |
| DEC-04 | Sibling-branch gate pattern mirrored exactly |
| DEC-05 | FIX-4 documentation-only; CNG bench = arbiter |
| DEC-06 | No gui/, no feed-format, no composite-beyond-integrity changes |
| RSK-01 | Installer self-access under the new share-mode — gate: NSIS loader behavior + CI launch + sandbox install round |
| RSK-02 | Non-elevated config-write breakage — gate: relauncher never writes config (verify in implementation) |
| RSK-03 | Legitimate-click refusal — gate: parity with sibling-branch condition (proxy control) |
| SEC-05 | No new processes (imported from composite design.md:422 — untouched by all fixes) |
| RSK-05 | Vendor-lane coordination (imported from tooling chain) — FIX-1 is a single-function minimal diff |
| FR-12 | Imported from the composite chain (the broken hardening this chain repairs) |
| RSK-04 | Vendor-lane stale state — measured before FIX-1 (last vendor commit 999a9294, owner lane) |
| RSK-06 | v3.9.3 is LIVE with the setpos crash on every language-verify/install path — re-release v3.9.4 owed immediately after this chain; the raw feed pair stays consistent-stale meanwhile (fail-safe) |
| DEC-07 | The setpos ABI sweep becomes the standing mechanical ABI-check for every future vendor call site (grep against the vendored signature, not trust) |
