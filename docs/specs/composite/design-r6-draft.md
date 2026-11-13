# Composite — r6 DRAFT (transport inversion of the prompt pipeline)

> **STATUS: DRAFT — NOT APPROVED.** This file is the proposed revision body for
> `design.md` (currently approved r5). It does NOT amend DEC-03/FR-01 until the
> owner approves opening the r6 chain; then it merges into `design.md` as r6,
> runs a fresh-context goldfish round, and only then may tasks consume its keys.
>
> Provenance (2026-11-07, two verification rounds):
> - Round 1 — adversarial review of the implemented T001–T006 code (verdict
>   EFFECTIVE-WITH-GAPS; headline: the 5157 pipeline is inert — its two config
>   keys are never written) + primary-source transport research
>   (FwpmNetEventSubscribe is in-tree, needs no audit policy).
> - Round 2 — hostile verification of the r6 proposal itself (verdict
>   SOUND-WITH-GAPS, gaps G1–G8, all sourced: learn.microsoft.com + upstream
>   issues #2114/#1807/#2085/#2132) + tree-grounded design pass (every claim
>   cited file:line from `composite/T003-T006-prompting`).
> - Two claims of the original proposal were CORRECTED by the hostile round:
>   (a) **no subLayerId field exists** in any FWPM_NET_EVENT_CLASSIFY_DROP
>   struct — attribution is filterId → filter → providerKey (log.c already
>   implements it); (b) **FWPM_NET_EVENT_ENUM_TEMPLATE0 cannot scope by event
>   type** (SDK `shared/fwpmtypes.h:1187-1193` — header-field conditions only);
>   type scoping stays at parse time where log.c already does it.

## 1. Target architecture (DEC-10, amends DEC-03/FR-01)

**DEC-10: prompt pipeline = dual-transport, net-event primary, 5157 fallback.**
One WFP net-event subscription feeds BOTH the log rows and the prompt pipeline;
the Security-audit 5157 pipeline (T002, `src/composite_eventlog.c`) becomes a
fallback that engages only under the conditions of FR-15. Foreign-filter drops
are log-only, never prompts.

### 1.1 PRIMARY: net-event subscription, owned once per engine lifetime

Today the subscription is created at engine init and then needlessly torn down
and recreated on **every** rule apply: `_wfp_applythread` calls
`_wfp_logunsubscribe` (`src/wfp.c:2179-2180`) and `_wfp_logsubscribe`
(`src/wfp.c:2219-2220`) around the filter work, while `_wfp_initialize`
already subscribes once at init (`src/wfp.c:386-390`) and `_wfp_uninitialize`
unsubscribes once at teardown (`src/wfp.c:429-430`). `_wfp_logsubscribe` is
already idempotent (CAS on `config.hnetevent`, `src/log.c:481-484`), so the
per-apply pair buys nothing but the G5 prompt-dead window and a per-apply
exposure to the upstream #2132 UAF class on this exact path.

r6 ownership and lifecycle:

- **Owner:** `config.hnetevent` stays the owner (`src/main.h:213`,
  `volatile HANDLE`); `_wfp_logsubscribe`/`_wfp_logunsubscribe`
  (`src/log.c:464-566`, `src/log.c:568-586`) stay the only writers. No new
  owner — the CAS guard already gives single-subscription semantics.
- **Created:** once per engine session, at the tail of `_wfp_initialize`
  after `FWPM_ENGINE_COLLECT_NET_EVENTS` is ensured (`src/wfp.c:348-391`);
  reached on first install-apply of the session (`_wfp_applythread` →
  `_wfp_initialize`, `src/wfp.c:2182-2184`) and the `-install` cmdline path
  (`src/main.c:3687`).
- **(Re)created:** additionally by heartbeat/BFE-restart recovery (Section 2)
  and by re-enable (`_wfp_uninitialize` resets `config.is_neteventset` FALSE
  at `src/wfp.c:444`, so the next install apply re-enters `src/wfp.c:348`).
- **Interplay with `_wfp_uninitialize`:** unchanged — teardown still
  unsubscribes (`src/wfp.c:429-430`), still stops the eventlog client
  (`src/wfp.c:432`), still restores the entry-state engine option
  (`src/wfp.c:434-445`).

**Apply churn removal (G5)** — `_wfp_applythread` (`src/wfp.c:2166-2239`)
changes exactly this:

- DELETE the unsubscribe at `src/wfp.c:2178-2180`.
- DELETE the resubscribe at `src/wfp.c:2218-2220`.
- KEEP: `lock_apply` acquire (`src/wfp.c:2173`), install branch
  (`src/wfp.c:2182-2199`), disable branch (`src/wfp.c:2201-2216`), wufix,
  interface state, profile save (`src/wfp.c:2228-2236`). The per-apply
  `_app_eventlog_start` hook (`src/wfp.c:2222-2226`) is superseded by the
  fallback engine (1.3); `_app_eventlog_stop` in the disable branch
  (`src/wfp.c:2210`) and teardown (`src/wfp.c:432`) stay.
- Consequence: with `config.hnetevent` already set, a stray
  `_wfp_logsubscribe` call is a no-op (`src/log.c:483-484`) — safe against
  residual call paths.

**Type scoping.** The subscription template stays empty as today
(FWPM_NET_EVENT_ENUM_TEMPLATE0 has no type field — SDK citation in header);
type scoping stays where it already is: `log_struct_to_f`
(`src/log.c:861-899`). For the **prompt tier** the classification additionally
accepts only `FWPM_NET_EVENT_TYPE_CLASSIFY_DROP` (CLASSIFY_DROP_MAC log-side
only): IPSEC_KERNEL_DROP has no user-attributable app in the prompt sense, and
CLASSIFY_ALLOW events are never prompts (`is_allow` already excluded from the
notification gate, `src/log.c:1541`).

### 1.2 Attribution (G1): provider check, cache, deletion race

The attribution chain already exists and lands the verdict on the log object:
`FwpmLayerGetById0` (`src/log.c:655`), the FLOW_ESTABLISHED skip
(`src/log.c:666-670`), the recv/accept direction fix (`src/log.c:672-673`),
`FwpmFilterGetById0` (`src/log.c:680`), and the provider test
`IsEqualGUID (filter_ptr->providerKey, &GUID_WfpProvider)` — provider
`{B0D553E2-…}` (`src/wfp.h:7`) — stored as `ptr_log->is_myprovider`
(`src/log.c:718-722`, `src/log.c:842`; field `src/main.h:285`).

- **"Blocked by us" = `is_myprovider == TRUE`.** The notification gate already
  requires it for net-event rows: `ptr_log->is_myprovider ||
  ptr_log->is_composite` (`src/log.c:1541`). r6 narrows this gate: the
  `is_composite` OR is removed for net-event rows and replaced for 5157 rows
  by the same provider verdict (5157 rows carry FilterRTID,
  `src/composite_eventlog.c:359`) — so foreign-filter drops (Defender Firewall
  blocks — upstream #2114 storm class) can never prompt on either transport.
  This kills the storm class structurally, not by throttling.
- **Attribution cache.** The two RPC round-trips per event run on the BFE
  delivery thread (`_wfp_logcallback` is the subscribe callback,
  `src/log.c:635`). r6 adds a per-filterId cache: pointer hashtable
  (`_r_obj_createhashtablepointer`, idiom `src/composite_publisher.c:90-91`)
  keyed by a ULONG fold of `filter_id`, value =
  `{is_ours, weight, filter_name, layer_name}`. On miss → the existing
  `FwpmFilterGetById0`/`FwpmLayerGetById0` calls populate it. **Invalidation
  is wholesale on apply**: filter GUIDs are recreated every apply
  (`_wfp_clearfilter_ids`, `src/wfp.c:530`, `src/wfp.c:892-899`); the apply
  path clears the table once per apply. Bounded by `MAP_CACHE_MAX`
  (`src/main.h:133`). Performance fix, not a correctness one.
- **Deletion race** (`src/log.c:682-688`: filter deleted between event and
  lookup — `FWP_E_FILTER_NOT_FOUND` or the NULL-with-success quirk):
  classified **foreign/log-only**. r6 emits a minimal log row
  (`is_myprovider = FALSE`, synthetic filter/layer names, never prompts — the
  narrowed gate at `src/log.c:1541` rejects it) so visibility is kept instead
  of today's silent drop. Retry is rejected: it would re-introduce per-event
  RPC storms for permanently-gone filters. Events referencing our own
  just-replaced filters during the apply window therefore log without
  prompting — acceptable, because apply-time is exactly when prompts are
  already held (`_wfp_isfiltersapplying` gates deploys,
  `src/composite_state.c:158-164`).

### 1.3 FALLBACK: 5157 audit path, engagement/retreat

The 5157 pipeline is the existing `composite_audit.c` (machine change, SEC-03)
+ `composite_eventlog.c` (EvtSubscribe client), both implemented and currently
inert: the gates read `IsCompositeAuditEnabled` (`src/wfp.c:2189`,
`src/main.c:3692`, `src/composite_audit.c:503`) and
`IsCompositeEventLogEnabled` (`src/wfp.c:2225`,
`src/composite_eventlog.c:34`) but nothing writes them.

Engagement (any one, gated by the machine-change consent):

- **(a) tamper/disabled collection** — the heartbeat (FR-15) reads
  `FwpmEngineGetOption0 (FWPM_ENGINE_COLLECT_NET_EVENTS)` and finds it FALSE
  (or unwritable) while prompts are wanted;
- **(b) user opt-in for mcast/bcast coverage** — the fork already requests
  `FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST|BCAST` by default (`IsExcludeInbound`
  default FALSE inverts into the mask, `src/log.c:600-602`), but a user who
  wants guaranteed inbound mcast/bcast prompt coverage can opt into the 5157
  path explicitly.

Engagement requires **both** `IsCompositeAuditEnabled == TRUE` (the
machine-wide change is consented) **and** the subcategory actually enabled
(`_app_audit_issubcategoryenabled`, `src/composite_audit.c:509-520`) — today
the client starts degraded instead of not starting
(`src/composite_eventlog.c:549-550`); r6 makes that a hard engagement
condition. The subscription itself is the existing single-flight-guarded
`_app_eventlog_start` (`src/composite_eventlog.c:492-500`).

Retreat: heartbeat sees collection healthy again for N consecutive beats
(hysteresis, default 3 — open question Q6) → stop the 5157 subscription
(`_app_eventlog_stop`, `src/composite_eventlog.c:557-574`); revert is NOT
touched (audit stays configured until disable/uninstall per SEC-03; retreat
only closes the subscription).

Tray/status states (the existing chain at `src/controls.c:663-684` status bar
and `src/controls.c:704-722` tooltip is re-keyed):

| State | Meaning | Surface |
| --- | --- | --- |
| healthy | net-event feed subscribed + collection ON | unchanged |
| degraded-primary | net-event feed dead and fallback NOT engaged | prompts dead; status + tooltip say so |
| fallback-active | 5157 feed delivering prompts | "fallback prompts (Security audit) active" |
| dead | engine down or both transports down | "prompts unavailable"; enforcement-degraded keeps precedence |

The existing accessors are re-semanticized rather than duplicated:
`_app_eventlog_ispromptdegraded` (`src/composite_eventlog.c:582-594`) becomes
the degraded-primary/fallback-active oracle of the feed module (FR-15), and
the never-called `_app_eventlog_ishealthy` (`src/composite_eventlog.c:576-580`)
gets its first caller: the heartbeat.

### 1.4 Unified feed: where the composite tier logic inserts

`ITEM_LOG` is the single wire format on both transports and does not change
(`src/main.h:246-292`; `is_composite` already exists, `src/main.h:291`).
Both transports queue onto `log_queue` (net events: `src/log.c:847`; 5157:
`src/composite_eventlog.c:429`) into `_app_logthread`
(`src/log.c:1493-1560`). r6 inserts exactly three things at the top of
`_app_logthread`:

1. **Unified LRU dedup** (Section 3.4, single choke point — covers both feeds
   because both arrive here).
2. **Prompt-worthiness classification**: `is_promptworthy` =
   `(is_myprovider && !is_allow) || (is_composite && attribution says ours)` —
   replacing the blanket OR at `src/log.c:1541`.
3. Nothing else. The admission/auto-add path (`src/log.c:1507-1522`), the
   file-log gate (`src/log.c:1548`), the UI-log gate (`src/log.c:1551-1553`),
   and the final deref (`src/log.c:1559`) are untouched — log rows remain
   gated by `IsLogEnabled`/`IsLogUiEnabled`/`IsNotificationsEnabled`
   (`src/log.c:1527-1534`) and **not** by prompt health; prompts are not
   gated by `IsLogEnabled`.

### 1.5 Prompt UX: endpoints natively correct

On the primary path the header fields land directly: `remote_addr4/6` from
`header.remoteAddrV4/V6`, `local_addr4/6` from `header.localAddrV4/V6`
(`src/log.c:786-809`), ports from `header.remotePort/localPort`
(`src/log.c:812-816`), direction with the recv/accept inbound fix
(`src/log.c:672-673`) — ITEM_LOG keeps local/remote straight by construction.

The fallback path has the port-swap bug: addresses are parsed
direction-correctly (`src/composite_eventlog.c:299-335`: inbound ⇒
`SourceAddress` is the remote peer) but ports are unconditional —
`remote_port = dest_port; local_port = source_port`
(`src/composite_eventlog.c:350-353`) — wrong for inbound (44/46), where the
remote port is `SourcePort`. r6 fixes it in the fallback:
`remote_port = is_inbound ? source_port : dest_port; local_port = is_inbound
? dest_port : source_port;` and deletes the stale "treat as OUTBOUND" comment.
The bug is thereby confined to and removed from the fallback path; the primary
path never had it.

## 2. Health & lifecycle (G2/G3/G5/G6 — FR-15)

### 2.1 Heartbeat

No unconditional periodic timer exists in the tree to piggyback on
(FileMonitor thread is the cadence precedent, `src/helper.c:1763-1809`, but
only runs when `IsEnableAppMonitor` is on). r6 adds a minimal dedicated thread
in the new feed module, following the FileMonitor creation idiom
(`_r_sys_createthread` + resume, `src/helper.c:1748-1749`) with one deliberate
divergence: the loop waits on a **stop event**
(`_r_sys_waitforsingleobject (hstop, 60000)`) instead of the self-terminate
pattern — `helper.c:1755` uses `_r_sys_terminatethread`, which is literally
`TerminateThread` (`vendor/routine/routine.h:6924-6931`) and is unsafe for a
thread that may hold a queued lock. Teardown joins via `SetEvent` + wait.

60-second beat, each beat performs:

1. **BFE service state** — SCM poll, the project's idiom
   (`OpenServiceW`+`QueryServiceStatus`, `src/helper.c:2225-2237`;
   `OpenSCManagerW`, `src/packages.c:475-485`). `NotifyServiceStatusChange`
   is rejected — no use anywhere in `src/`, and polling every 60 s is cheap
   and matches the idiom. STOPPED/STOP_PENDING → dead → recovery (2.2).
2. **Engine option heartbeat (G3's reliable detector)** —
   `FwpmEngineGetOption0 (FWPM_ENGINE_COLLECT_NET_EVENTS)`: needs only read
   access, works even when collection was tampered off, doubles as an
   engine-liveness probe (RPC failures = engine dead).
3. **Subscription liveness** — `config.hnetevent != NULL` (`src/main.h:213`)
   plus the fallback transport's checks. Event-silence is explicitly NOT a
   liveness signal (silence is normal on a quiet machine).

Beat outcomes drive the state machine (Section 1.3), refresh the tray via
`_app_setinterfacestate` (`src/controls.c:640`), and trigger the
subscribe-retry of 2.3.

### 2.2 BFE restart (G2): engine handle redesign + recovery

Today `_wfp_getenginehandle` caches the engine handle in a one-time
`R_INITONCE` forever (`src/wfp.c:42-100`: init_once at :44, open at :64,
retry-on-`EPT_S_NOT_REGISTERED` at :72-84, hard `NtTerminateProcess` on
first-open failure at :89). A BFE restart silently kills the subscription and
every non-persistent filter, and nothing in `src/` notices.

**Redesign (exact):** replace the init-once with queued-lock-guarded
re-openable state, keeping the function signature (`src/wfp.h:47`):

- `static R_QUEUED_LOCK lock_engine` + `static volatile HANDLE hengine` +
  `static volatile BOOLEAN is_firstopen_done`.
- `_wfp_getenginehandle ()`: acquire `lock_engine` **shared** → return cached
  handle if non-NULL; on NULL: release, acquire **exclusive**, re-check
  (double-checked), run the existing open logic verbatim (session key
  generation `src/wfp.c:53`, `FWPM_SESSION0` fields :57-62, retry loop
  :72-84). The hard-fail `NtTerminateProcess` (`src/wfp.c:89`) is kept **only**
  for the first-ever open (process was never viable); on a **re**-open failure
  the function returns NULL and the state machine goes to `dead` (honest) —
  the app was healthy before, it must not suicide.
- New `_wfp_resetenginehandle ()` (declared in `src/wfp.h`): exclusive lock →
  `FwpmEngineClose0` the cached handle (tolerate errors — it may already be
  dead), NULL the cache. All call sites keep working unchanged — the tree
  already re-reads the handle at every use point (`_wfp_applythread`
  `src/wfp.c:2176`, callbacks `src/log.c:655,680`).

**Recovery sequence:** the heartbeat does not touch WFP directly. It queues a
synthesized install-apply context on `wfp_queue` — the exact idiom of
`_app_install_run`/apply: `_r_freelist_allocateitem (&context_free_list)` +
`context->is_install = TRUE` + `_r_workqueue_queueitem (&wfp_queue,
&_wfp_applythread, context)` (`src/main.c:31-36`). `wfp_queue` is
single-threaded (`src/main.c:1866`) — that is the recursion/re-entrancy guard:
if an apply is already in flight (`_wfp_isfiltersapplying`, `src/wfp.c:102-105`,
cheap pre-check before queueing) the heartbeat skips — the in-flight apply
re-opens the handle through the redesigned getter anyway.
`_wfp_applythread`'s install branch already does everything BFE-restart
recovery needs: `_wfp_initialize` re-creates provider/sublayer if gone
(`src/wfp.c:258-342`), installs filters (`src/wfp.c:2186`), re-materializes
publisher permits and session decisions
(`_app_publisher_applyall`/`_app_state_applyall`, `src/wfp.c:2197-2199`), and
with the churn removed (1.1) it re-subscribes — the recovery sequence
explicitly calls `_wfp_logunsubscribe`-then-`_wfp_logsubscribe` once around
the reset (the stale handle value must not be reused as a live subscription
key). This closes the documented backlog item "session filters vanish on BFE
service restart until next rule-apply" (`docs/BACKLOG.md:69-70`).

### 2.3 Subscribe failure (G6)

`FwpmNetEventSubscribe` can fail repeatedly with undocumented 0x70 (upstream
#2085/#2002/#1515/#1710). Today: one error dialog or log line
(`src/log.c:539-553`) and permanent silence. r6: the heartbeat owns retry —
when `config.hnetevent == NULL` and collection is healthy, attempt
`_wfp_logsubscribe` with exponential beat backoff (1, 2, 4, 8, capped at 10
beats = 10 min), state stays `degraded-primary` the whole time (honest, never
silently dead), the error dialog stays first-attempt-only (subsequent attempts
log `LOG_LEVEL_INFO`). The toolbar enable/disable side effects
(`src/log.c:551-553`) ride each attempt's outcome as today.

## 3. Fixes folded in (round-1 adversarial review — still mandatory)

### 3.1 S4: lock-across-`_wfp_destroyfilters_array` hang

Affected sites: `_app_state_clearlocked` (`src/composite_state.c:75-76` —
under `lock_state` from uninitialize :92-99, timer :279-290, revokeapp
:428-437), `_app_state_deploy`'s stale-GUID destroy
(`src/composite_state.c:140-141`), and `_app_publisher_revokepath`
(`src/composite_publisher.c:98-99` — under `lock_publisher` from querypath
:258-269, :342-347, uninitialize :687-693). `_wfp_destroyfilters_array`
messages the window around the work (`_app_initinterfacestate`/
`_app_restoreinterfacestate`, `src/wfp.c:966,993`) while holding
`lock_transaction` shared (`src/wfp.c:968-991`) — a UI thread blocked on the
module-exclusive lock while the holder pumps messages = hang.

**New ownership (exact):** each site swaps the `PR_ARRAY` out under the module
lock (`_r_obj_swapreference` into a local — vendor helper, used at
`src/log.c:755`), releases the module lock, then calls
`_wfp_destroyfilters_array` on the swapped-out array. The snapshot pattern
already exists in-family: `_app_publisher_revalidate`
(`src/composite_publisher.c:587-606`) snapshots paths under `lock_publisher`
and verifies outside. `_app_state_clearfilters` (`src/composite_state.c:478-496`)
and `_app_publisher_clearfilters` (`src/composite_publisher.c:662-680`) stay
clear-under-lock-only (their GUIDs are already dead at that point). The exit
path (`WM_DESTROY` → uninitializes, `src/main.c:2276-2277`) inherits the fix
automatically.

### 3.2 Settings toggles become real settings

Settings surface (user-visible, one checkbox, two keys):

- **"Allow Security-audit fallback prompts (machine-wide audit policy)"** in
  the settings dialog, wired with the existing idiom: read to initialize
  control state, write via `_r_config_setboolean` in the `WM_COMMAND` handler
  (pattern: `src/main.c:1347` `IsLogEnabled`). Writes **both** keys:
  `IsCompositeAuditEnabled` (consent for the machine change; FALSE remains the
  shipped default) and `IsCompositeEventLogEnabled` (the 5157 client gate).
  Unchecking + apply runs the existing revert (`_app_audit_revert` via the
  disable branch, `src/wfp.c:2209`) and `_app_eventlog_stop`
  (`src/wfp.c:2210`).
- mcast/bcast coverage stays on the existing `IsExcludeInbound` semantics
  (`src/log.c:601-602`) — no new key.
- Read sites stay exactly where they are — the change is the write points,
  not the reads. New strings through the i18n pipeline (NFR-05).

### 3.3 WinVerifyTrust amplification (publisher cache keyed path+mtime)

Cache: `src/composite_publisher.c:284-291` (mtime-hit skips verify;
`WinVerifyTrust` outside the lock at :297). Caps:

- **Per-path min-interval rate limit:** `_app_publisher_querypath` gains a
  `last_attempt` tick per entry; even when mtime moved, a re-verify runs at
  most once per 30 s per path (tick stored in `ITEM_PUBLISHER_PATH`,
  `src/composite_publisher.c:26-40`).
- **Held-counter cap:** `_app_state_holdpending` increments unboundedly
  (`src/composite_state.c:508-517`). Cap 256: above the cap the event is not
  counted (still batch-logged by the normal log path); the tray shows the
  capped count via the existing `_app_state_getheldtotal`.
- **Profile-save debounce:** composite-triggered saves fire per event today
  (auto-add: `src/log.c:1520`; allow decision: `src/notifications.c:431`).
  Debounce: one `TpAllocTimer`-based coalescing save, 10 s, module-level
  single timer (timer idiom: `src/composite_state.c:328-336`);
  user-initiated saves stay synchronous.

### 3.4 Dedup: bounded LRU at the unified choke point

Replace the single-slot 2 s window (`src/composite_eventlog.c:84-87,412-425`)
with:

- **Key:** `(app_hash, af, protocol, direction, remote_addr, remote_port)` —
  composed like `_app_getloghash` (`src/log.c:150-171`) minus `local_port`
  (ephemeral). 64-bit mixed hash (mix idiom already present,
  `src/composite_eventlog.c:119-128`).
- **Size/eviction:** 256-entry hashtable (`hash → last_tick`), oldest-tick
  eviction when full (same "evict the oldest" policy as the log-table/UI-list
  pair, `src/log.c:437-451`); guard lock is a module `R_QUEUED_LOCK`.
  256 × ~16 B ≈ 4 KB — trivial bound.
- **Window:** 2000 ms, unchanged value, renamed `COMPOSITE_PROMPT_DEDUP_MS`.
- **Placement: `_app_logthread` entry** (`src/log.c:~1500`, before the gates
  at :1527) — the single choke point through which BOTH feeds' output passes
  (1.4), so the dual-feed double-count item (`docs/BACKLOG.md:67-68`) dies
  with it. Only prompt-suitable events consult the LRU; log rows keep their
  own existing dedup (`_app_islogfound`, `src/log.c:430-431`). A dropped
  duplicate skips the body and falls through to the existing final deref
  (`src/log.c:1559`) — no leak, no early return.
- The 5157 module-local dedup (`src/composite_eventlog.c:408-425`) is deleted
  with the single-slot mechanism.

### 3.5 Tier-0 session-decision check

`_app_notify_istierscovered` (`src/notifications.c:236-267`) currently checks
app-enabled (:244), matching rule (:249), publisher (:259-263) — not session
decisions. A user who answered "until restart / once" must not be re-prompted.
**Spec:** insert tier0 at the top:

```c
// tier0: an active session decision (once/until-restart) already covers
// this app (FR-04) — covered means covered, regardless of transport
BOOLEAN is_block, is_once;
if (_app_state_getdecision (ptr_app->app_hash, &is_block, &is_once))
    return TRUE;
```

`_app_state_getdecision` exists (`src/composite_state.c:381-417`) and
`composite_state.h` is already included in `notifications.c`
(`src/notifications.c:7`) — no new include, no ABI change.

### 3.6 Audit-leak fixes carried into the fallback module

- **Revert with missing inventory must warn loudly:** today a missing
  inventory is a silent no-op (`src/composite_audit.c:420-425`). r6: warn
  loudly (`LOG_LEVEL_WARNING` + status surface) when the inventory is missing
  **but** there is residue evidence — `IsCompositeAuditEnabled` still TRUE at
  revert time, or the subcategory's FAILURE bit currently set. The genuinely
  never-enabled case stays silent. Restore policy unchanged: no inventory ⇒
  warn-and-leave, never a guessed restore (SEC-03).
- **Sidecar hardening (asInvoker + user-writable profile dir):** the inventory
  is written with NULL security attrs (`src/composite_audit.c:110`). (a) write
  with the explicit user+admins DACL — `_app_log_getdacl` already exists
  (`src/log.c:13-70`); (b) write a redundant copy of the four prior values
  under an admin-only registry location (`HKLM\SOFTWARE\<app>\audit-inventory`)
  at enable; at revert, sidecar and HKLM copy are cross-checked — mismatch ⇒
  warn-and-leave (the strict-format gate at :182-189 stays).
- **Enable-status checks honored at both call sites:** check the return value
  of `_app_audit_enable` at `src/wfp.c:2189-2190` and `src/main.c:3692-3693`;
  on failure log + honest degraded state. Additionally, the 5157 client
  requires `_app_audit_issubcategoryenabled () == TRUE` before subscribing
  (1.3), replacing start-then-mark-degraded (`src/composite_eventlog.c:549-550`).

## 4. Data & structures

- **Module layout:**
  - **NEW `src/composite_feed.c/.h`** — the unified feed owner: prompt tier
    classification, attribution cache, LRU dedup, heartbeat thread, state
    machine (healthy/degraded-primary/fallback-active/dead), BFE-recovery
    trigger, subscribe retry. All entry points declared in `composite_feed.h`
    and called only through those declarations (documented ABI practice —
    incident history: `docs/specs/hardening-round-1/verification.md:179-190`).
  - **`src/composite_eventlog.c` stays, thin** — the 5157 client as named.
    Loses: single-slot dedup (3.4), port swap (1.5), start-then-degrade (3.6).
    Its `is_promptsdegraded` flags move to the feed state machine;
    `_app_eventlog_ishealthy` gains its first caller (the heartbeat).
  - **`src/log.c` / `src/wfp.c`** — subscription lifecycle per 1.1;
    attribution per 1.2; `_wfp_getenginehandle` per 2.2.
  - **`src/composite_audit.c`** — leak fixes per 3.6.
  - **`src/controls.c`** — the four tray/status states (1.3).
- **New/changed structs:**
  - `ITEM_FEED_STATE` (feed module statics): enum state + retry-beat counter +
    healthy-beat counter + heartbeat thread/stop-event handles. Private to
    `composite_feed.c`.
  - `COMPOSITE_ATTRIB_ENTRY { BOOLEAN is_ours; UINT8 weight; PR_STRING
    filter_name; PR_STRING layer_name; }` — pointer-hashtable value
    (ownership contract: table derefs on removal, pointer-table pattern
    `src/composite_state.c:357-360`).
  - `ITEM_LOG` unchanged (`src/main.h:246-292`); no sidecar format changes
    (`src/composite.h:8-10`; audit inventory gains the HKLM mirror, same
    on-disk format).
- **DEC-04 (umbrella) non-interference:** nothing here touches the Lockdown
  recipe; the r5-prescribed T007 sublayer pin is orthogonal.

## 5. Task breakdown for the gate chain (continues T000–T016 as T017–T024)

- **T017 — Unified feed module.** `src/composite_feed.c/.h` (state machine,
  prompt classification, `_app_logthread` insertion points); LRU dedup choke
  point (3.4); remove the 5157 module-local dedup and port swap (1.5).
  Files: composite_feed.c/h, log.c, composite_eventlog.c, simplewall.vcxproj.
  Verify: bench step 7 (40-process burst → 1 prompt, dedup bounded). Keys:
  DEC-10, FR-15, FR-05 (FR-01 as amended).
- **T018 — Apply-churn removal.** Delete the per-apply
  unsubscribe/resubscribe pair (`src/wfp.c:2178-2180,2218-2220`); lifecycle
  owned by `_wfp_initialize`/`_wfp_uninitialize`; remove the per-apply
  `_app_eventlog_start` hook. Files: wfp.c. Verify: 40 applies → zero
  churn, prompt survives an apply. Keys: DEC-10, FR-15 (G5; #2132 note).
- **T019 — Attribution cache + foreign log-only + deletion-race
  classification.** Per-filterId cache with wholesale apply-invalidation;
  narrowed prompt gate at `src/log.c:1541`; FWP_E_FILTER_NOT_FOUND ⇒ log-only
  row; 5157 rows attributed via FilterRTID. Files: log.c, composite_feed.c,
  composite_eventlog.c. Verify: bench step 2 (foreign block → log row, no
  prompt). Keys: FR-16, DEC-10 (G1, #2114).
- **T020 — Heartbeat + state machine + tray states.** 60 s monitor thread
  (SCM poll idiom, `FwpmEngineGetOption0` probe, stop-event join); four-state
  tray/status surfacing; i18n. Files: composite_feed.c/h, controls.c,
  resources. Keys: FR-15, RSK-01 (G3).
- **T021 — BFE-restart recovery + engine-handle redesign.** Queued-lock
  re-openable `_wfp_getenginehandle` + `_wfp_resetenginehandle`
  (`src/wfp.c:42-100`, declaration in `src/wfp.h:47`); heartbeat-driven
  recovery via synthesized apply context on `wfp_queue`. Files: wfp.c/h,
  composite_feed.c. Verify: bench step 4 (restart bfe → filters +
  subscription restored, prompt works). Keys: FR-15, DEC-10 (G2; closes
  `docs/BACKLOG.md:69-70`).
- **T022 — Fallback engagement + settings surface + subscribe retry.**
  Engagement/retreat logic (1.3); settings checkbox writing both keys (3.2);
  heartbeat subscribe retry with backoff (2.3); enable-status checks (3.6).
  Files: composite_feed.c, composite_eventlog.c, composite_audit.c, main.c,
  wfp.c. Keys: FR-15, RSK-01, SEC-03 (G6).
- **T023 — Folded hardening: S4 + amplification + tier0 + audit-leak.**
  Snapshot-under-lock/destroy-outside (3.1); WinVerifyTrust rate limit + held
  cap + save debounce (3.3); tier0 (3.5); audit inventory warn-on-missing +
  DACL + HKLM mirror (3.6). Files: composite_state.c, composite_publisher.c,
  notifications.c, composite_audit.c, log.c. Keys: SEC-03, FR-16, backlog
  S4/S3.
- **T024 — BENCH protocol validation (7-step empirical test) +
  upstream-candidate extraction.** Extend the sandbox bench with the r6
  7-step probe (below) + `/W4` + `/analyze` clean + upstream-candidate
  review: apply-churn removal (T018) and port-swap fix (1.5) are
  upstream-clean by construction — assess as DEC-09 contribution candidates
  like the #2167 fix. Keys: NFR-06, OPS-04, OPS-03, DEC-09, FR-15.

## 6. Open questions for the goldfish round

1. **Fallback auto-engage vs opt-in:** prior-consent only
   (`IsCompositeAuditEnabled` already TRUE) vs first-time in-session prompt.
   Default proposal: prior-consent only.
2. **Foreign-filter blocks in the log:** always visible this round, or a new
   `IsExcludeForeign` gate? Default proposal: always visible; key deferred.
3. **LRU size/window:** fixed 256 / 2000 ms vs config-driven. Default
   proposal: fixed constants (app idiom), revisit if bench shows a flood
   pattern (G4 push-burst behavior undocumented).
4. **`FWPM_ENGINE_COLLECT_NET_EVENTS` policy:** keep capture-and-restore
   (`src/wfp.c:348-391,434-445`) + heartbeat re-assert (detect-and-repair,
   no persistence change). Default proposal: keep + re-assert.
5. **Deletion-race rows:** emit synthetic log-only row (visibility) vs keep
   silent drop. Default proposal: emit (apply window is short).
6. **Retreat hysteresis:** fallback retreats after 3 healthy beats
   mid-session; audit configuration itself stays until disable/uninstall
   (SEC-03) so re-engage is instant and consent-covered. Default proposal:
   retreat after 3 beats.

## Appendix — BENCH protocol (7 steps, ~15 min, Win11, fork exe, admin cmd)

Prep: `netsh wfp show filters file=%TEMP%\f.xml` (grep the {9FEE6F59} sublayer
block, record filterIds); `netsh wfp show state file=%TEMP%\w0.xml` (confirm
"Collect Net Events" TRUE).

1. **Own-filter delivery (2 min).** Block `%SystemRoot%\System32\curl.exe`;
   `curl -4 http://example.com`. PASS: prompt ≤2 s AND Log row names our
   rule, is_myprovider=TRUE.
2. **Cross-filter noise (1 min).** Enable Windows Firewall "Block all
   outbound" for 10 s with our filters ON. PASS: log rows attributed to
   foreign filterIds produce NO prompt (G1/#2114).
3. **Fallback engagement (2 min).** Disable COLLECT_NET_EVENTS (option off,
   admin) with fallback consent ON. PASS: heartbeat flips tray to
   fallback-active, prompts continue via 5157; restore option → retreat
   after 3 beats.
4. **BFE restart (3 min).** `net stop bfe`, 10 s, `net start bfe`. PASS:
   filters + subscription restored, probe prompts again (today this FAILS —
   feed dies silently — that failure is the G2 evidence).
5. **Apply churn (1 min).** 40 applies (add/remove dummy rules). PASS: no
   unsubscribe/resubscribe churn, prompt survives each apply.
6. **Loopback (2 min).** Block the client app; `curl http://127.0.0.1:8099`
   against a local listener. PASS: log row with Loopback=yes. (Loopback
   collection is UNVERIFIED by docs — this settles it.)
7. **Burst (3 min).** ~500 attempts against a blocklisted target. PASS: UI
   responsive, LRU bounded, no hang (upstream #1807 was a hang under flood).
