// simplewall (composite fork)
// Composite Phase 1 — prompting session state (T005 durations, T006
// single-flight). FR-04/DATA-01: "once" and "until-restart" prompt
// decisions live in memory only and deploy as composite-owned WFP
// filters; they never touch ptr_app->is_enabled, never enter rules_list
// (storage rule: _app_db_save_rule persists any non-readonly entry and
// _app_db_save_app persists is_enabled — both paths are avoided by
// keeping the filters entirely module-local) and never reach profile.xml.
// FR-05: novel connections arriving while a prompt is visible are
// counted for batch review; WFP is left alone (the unconditional
// FWP_ACTION_BLOCK at FWW_LOWEST already blocks them).
//
// Module-local exclusive lock (composite_audit.c precedent); no UI calls
// and no lock_rules/lock_apps acquisition while holding it.

#include "global.h"
#include "composite_state.h"

#include "composite.h"

typedef struct _ITEM_STATE_DECISION
{
	PR_ARRAY guids; // composite-owned deployed filter GUIDs

	PTP_TIMER htimer; // "once" expiry timer (NULL = until restart)

	ULONG app_hash;

	LONG64 expires; // unix time; 0 = until restart

	BOOLEAN is_block;
	BOOLEAN is_once;
} ITEM_STATE_DECISION, *PITEM_STATE_DECISION;

static R_QUEUED_LOCK lock_state = PR_QUEUED_LOCK_INIT;

static PR_HASHTABLE state_decisions = NULL; // app_hash -> PITEM_STATE_DECISION (pointer table owns the allocation ref)
static PR_HASHTABLE state_held = NULL; // app_hash -> ULONG (held-pending count, T006)

static VOID NTAPI _app_state_dereferencedecision (
	_In_ PVOID entry
)
{
	PITEM_STATE_DECISION ptr_decision = (PITEM_STATE_DECISION)entry;

	if (ptr_decision->guids)
		_r_obj_clearreference ((PVOID_PTR)&ptr_decision->guids);

	if (ptr_decision->htimer)
	{
		TpReleaseTimer (ptr_decision->htimer);
		ptr_decision->htimer = NULL;
	}
}

NTSTATUS _app_state_initialize (VOID)
{
	// composite T005/T006: in-memory session state; sidecar persistence
	// is T009 scope (composite_state.h) — deliberate memory-only contract
	// so DATA-01 can never be violated by a session decision
	state_decisions = _r_obj_createhashtablepointer (0x04);
	state_held = _r_obj_createhashtable (sizeof (ULONG), 0x04, NULL);

	return STATUS_SUCCESS;
}

// S4/P1-1 (2026-11-10): _wfp_destroyfilters_array messages the UI
// (toolbar/statusbar). Destroying filters while holding the exclusive
// lock_state deadlocks any UI thread blocked on the same lock while the
// holder SendMessages it (the P1-1 hang). Under the lock we now only
// DETACH the decision's live resources; the caller destroys the detached
// GUID list outside the lock. MUST run while the decision is still
// referenced (the table's cleanup callback derefs on removal).
static PR_ARRAY _app_state_detachlocked (
	_Inout_ PITEM_STATE_DECISION ptr_decision
)
{
	PR_ARRAY guids = ptr_decision->guids;

	ptr_decision->guids = NULL;

	if (ptr_decision->htimer)
	{
		TpReleaseTimer (ptr_decision->htimer);
		ptr_decision->htimer = NULL;
	}

	return guids;
}

// destroy a detached (still-owned) GUID list outside lock_state; tolerates
// a gone engine handle at exit like the previous in-lock path did
static VOID _app_state_destroyguids (
	_In_opt_ PR_ARRAY guids
)
{
	if (!guids)
		return;

	if (!_r_obj_isempty2 (guids) && _wfp_isfiltersinstalled ())
		_wfp_destroyfilters_array (_wfp_getenginehandle (), guids, DBG_ARG);

	_r_obj_dereference (guids);
}

VOID _app_state_uninitialize (VOID)
{
	PITEM_STATE_DECISION ptr_decision = NULL;
	PR_LIST detached;
	PR_ARRAY guids;
	ULONG_PTR enum_key = 0;

	// S4/P1-1: detach everything under the lock, destroy outside it
	// (same snapshot pattern as _app_publisher_revokeexpired)
	detached = _r_obj_createlist (0x04, NULL);

	_r_queuedlock_acquireexclusive (&lock_state);

	if (state_decisions)
	{
		while (_r_obj_enumhashtablepointer (state_decisions, (PVOID_PTR)&ptr_decision, NULL, &enum_key))
		{
			// session ends: "once"/"until-restart" filters die with it (FR-04)
			guids = _app_state_detachlocked (ptr_decision);

			if (guids)
				_r_obj_addlistitem (detached, guids, NULL); // list takes our ownership ref
		}

		_r_obj_clearhashtable (state_decisions); // derefs (and frees) every decision
	}

	if (state_held)
		_r_obj_clearhashtable (state_held);

	_r_queuedlock_releaseexclusive (&lock_state);

	while (!_r_obj_isempty2 (detached))
	{
		guids = (PR_ARRAY)_r_obj_getlistitem (detached, 0);

		if (!guids) // /analyze C6011: detached slots are never null by construction; cheap insurance
			break;

		if (!_r_obj_isempty2 (guids) && _wfp_isfiltersinstalled ())
			_wfp_destroyfilters_array (_wfp_getenginehandle (), guids, DBG_ARG);

		_r_obj_removelistitem (detached, 0); // list derefs our ownership ref
	}

	_r_obj_dereference (detached);
}

// deploy the decision's filters inside the standard transaction pattern
// (mirrors _wfp_createappfilters: shared lock_transaction + tri-state
// _wfp_transact_start, hardening round 1)
static BOOLEAN _app_state_deploy (
	_Inout_ PITEM_STATE_DECISION ptr_decision,
	_In_ PITEM_APP ptr_app,
	_In_opt_ PITEM_LOG ptr_log
)
{
	ITEM_FILTER_CONFIG filter_config;
	PR_STRING rule_string = NULL;
	R_STRINGREF rule_sr;
	LPCWSTR filter_name;
	HANDLE engine_handle;
	LPCGUID guid;
	ENUM_TRANSACT_STATE transact_state;
	UINT8 weight;
	FWP_ACTION_TYPE action;
	BOOLEAN is_intransact;
	BOOLEAN is_locked = FALSE;
	BOOLEAN is_success = FALSE;

	engine_handle = _wfp_getenginehandle ();

	if (!engine_handle || !_wfp_isfiltersinstalled ())
		return FALSE;

	// T003-T006 goldfish finding 2: destroy+clear stale GUIDs from previous
	// deploys before re-deploying (the array was append-only across applies)
	if (!_r_obj_isempty2 (ptr_decision->guids) && _wfp_isfiltersinstalled ())
		_wfp_destroyfilters_array (engine_handle, ptr_decision->guids, DBG_ARG);

	_r_obj_clearreference ((PVOID_PTR)&ptr_decision->guids);

	// a "once" decision without its connection context can only mean a
	// re-deploy (rule-apply) — it must NEVER be silently upgraded to an
	// app-wide scope; the applyall caller skips once entries instead
	if (ptr_decision->is_once && !ptr_log)
		return FALSE;

	filter_name = _r_obj_getstring (ptr_app->display_name);

	if (!filter_name)
		filter_name = _r_obj_getstringordefault (ptr_app->short_name, L"<composite>");

	action = ptr_decision->is_block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;

	if (_wfp_isfiltersapplying ())
	{
		// an apply is in flight on this session — our adds join its
		// transaction (BFE transactions are session-wide); never commit
		// what we do not own
		is_intransact = TRUE;
	}
	else
	{
		_r_queuedlock_acquireshared (&lock_transaction);

		is_locked = TRUE;

		transact_state = _wfp_transact_start (engine_handle, DBG_ARG);

		if (transact_state == TXN_FAILED)
		{
			// atomic apply no longer possible upstream; deploy would be a
			// lie — leave it to the next full apply (_app_state_applyall)
			_r_log (LOG_LEVEL_WARNING, NULL, L"composite_state", L"transaction unavailable; session decision deferred", (LONG)transact_state);

			_r_queuedlock_releaseshared (&lock_transaction);

			return FALSE;
		}

		is_intransact = (transact_state == TXN_IN_PROGRESS);
	}

	// "once" scopes the decision to the exact reported connection and
	// must not override explicit user block rules: permit at FWW_RULE_USER
	// (below FWW_RULE_USER_BLOCK), block at FWW_RULE_USER_BLOCK. App-wide
	// session decisions sit at the same weights the permanent decisions
	// use (FWW_APP), so rule precedence is unchanged either way.
	if (ptr_decision->is_once && ptr_log)
	{
		weight = ptr_decision->is_block ? FWW_RULE_USER_BLOCK : FWW_RULE_USER;

		rule_string = _app_formataddress (ptr_log->af, 0, &ptr_log->remote_addr, ptr_log->remote_port, FMTADDR_AS_RULE);

		if (rule_string)
		{
			filter_config.direction = ptr_log->direction;
			filter_config.protocol = ptr_log->protocol;
			filter_config.af = ptr_log->af;

			_r_obj_initializestringref2 (&rule_sr, &rule_string->sr);

			_wfp_createrulefilter (
				engine_handle,
				ptr_app->type,
				filter_name,
				ptr_app->app_hash,
				&filter_config,
				&rule_sr,
				NULL,
				weight,
				action,
				FWPCOMPOSITE_FLAG_SESSIONFILTER, // FR-04: session-only, never persistent
				ptr_decision->guids
			);
		}
	}
	else
	{
		weight = ptr_decision->is_block ? FWW_RULE_USER_BLOCK : FWW_APP;

		_wfp_createrulefilter (
			engine_handle,
			ptr_app->type,
			filter_name,
			ptr_app->app_hash,
			NULL,
			NULL,
			NULL,
			weight,
			action,
			FWPCOMPOSITE_FLAG_SESSIONFILTER, // FR-04: session-only, never persistent
			ptr_decision->guids
		);
	}

	if (!is_intransact)
		_wfp_transact_commit (engine_handle, DBG_ARG);

	is_success = !_r_obj_isempty2 (ptr_decision->guids);

	// secure the freshly created filters (upstream re-secures all provider
	// filters at the end of a full apply; a mid-session deploy must do it
	// itself — benign failure while another transaction still owns them)
	if (is_success)
	{
		for (ULONG_PTR i = 0; i < _r_obj_getarraysize (ptr_decision->guids); i++)
		{
			guid = (LPCGUID)_r_obj_getarrayitem (ptr_decision->guids, i);

			if (guid)
				_app_setfiltersecurity (engine_handle, guid, TRUE, DBG_ARG);
		}
	}

	if (is_locked)
		_r_queuedlock_releaseshared (&lock_transaction);

	if (rule_string)
		_r_obj_dereference (rule_string);

	return is_success;
}

static VOID NTAPI _app_state_expired_callback (
	_Inout_ PTP_CALLBACK_INSTANCE instance,
	_Inout_opt_ PVOID context,
	_Inout_ PTP_TIMER timer
)
{
	PITEM_STATE_DECISION ptr_decision;
	PR_ARRAY guids = NULL;
	ULONG app_hash = PtrToUlong (context);

	// "once" expiry: silently remove the session filters; the next
	// connection re-prompts through the normal pipeline (FR-04)
	_r_queuedlock_acquireexclusive (&lock_state);

	ptr_decision = (PITEM_STATE_DECISION)_r_obj_findhashtablepointer (state_decisions, app_hash);

	if (ptr_decision)
	{
		// S4/P1-1: detach under the lock, destroy outside it
		guids = _app_state_detachlocked (ptr_decision);

		_r_obj_removehashtableitem (state_decisions, app_hash); // table derefs (frees)
	}

	_r_queuedlock_releaseexclusive (&lock_state);

	_app_state_destroyguids (guids);
}

BOOLEAN _app_state_decide (
	_In_ PITEM_APP ptr_app,
	_In_ BOOLEAN is_block,
	_In_ BOOLEAN is_once,
	_In_opt_ PITEM_LOG ptr_log,
	_In_opt_ HWND hwnd
)
{
	PITEM_STATE_DECISION ptr_decision;
	LARGE_INTEGER timestamp;
	FILETIME file_time;
	PTP_TIMER htimer;
	LONG64 current_time;

	if (!ptr_app || !state_decisions)
		return FALSE;

	// replace any previous session decision for this app
	_app_state_revokeapp (ptr_app->app_hash);

	ptr_decision = (PITEM_STATE_DECISION)_r_obj_allocate (sizeof (ITEM_STATE_DECISION), &_app_state_dereferencedecision);

	ptr_decision->app_hash = ptr_app->app_hash;
	ptr_decision->is_block = is_block;
	ptr_decision->is_once = is_once;
	ptr_decision->guids = _r_obj_createarray (sizeof (GUID), 0x04, NULL);

	current_time = _r_unixtime_now ();

	htimer = NULL;

	if (is_once)
	{
		ptr_decision->expires = current_time + STATE_ONCE_EXPIRY_SECONDS;

		if (NT_SUCCESS (TpAllocTimer (&htimer, &_app_state_expired_callback, ULongToPtr (ptr_app->app_hash), NULL)))
		{
			_r_unixtime_to_filetime (&file_time, ptr_decision->expires);

			_r_calc_filetime2largeinteger (&timestamp, &file_time);

			TpSetTimer (htimer, &timestamp, 0, 0);

			ptr_decision->htimer = htimer;
		}
		else
		{
			ptr_decision->expires = 0; // degrade to "until restart" lifetime
		}
	}
	else
	{
		ptr_decision->expires = 0;
	}

	if (!_app_state_deploy (ptr_decision, ptr_app, ptr_log))
	{
		_r_obj_dereference (ptr_decision); // never entered the table

		return FALSE;
	}

	_r_queuedlock_acquireexclusive (&lock_state);

	// the allocation reference becomes the table's ownership reference
	// (vendor pointer-table contract: add stores the raw pointer, cleanup
	// derefs on removal — same pattern as _app_addapplication/apps_table)
	_r_obj_addhashtablepointer (state_decisions, ptr_app->app_hash, ptr_decision);

	_r_queuedlock_releaseexclusive (&lock_state);

	// the decision covers the held-pending connections (T006 batch
	// review) — the hold release itself happens through the revokeapp
	// fold at decide's supersede step above (S3, 2026-11-10)

	if (hwnd)
		_app_listview_updateitemby_param (hwnd, ptr_app->app_hash, TRUE);

	_r_log (
		LOG_LEVEL_INFO,
		NULL,
		L"composite_state",
		ptr_app->real_path ? ptr_app->real_path->buffer : NULL,
		(LONG)((is_block ? 0x100 : 0) | (is_once ? 0x200 : 0))
	);

	return TRUE;
}

BOOLEAN _app_state_getdecision (
	_In_ ULONG app_hash,
	_Out_opt_ PBOOLEAN is_block,
	_Out_opt_ PBOOLEAN is_once
)
{
	PITEM_STATE_DECISION ptr_decision;
	BOOLEAN is_present = FALSE;

	if (is_block)
		*is_block = FALSE;

	if (is_once)
		*is_once = FALSE;

	if (!state_decisions)
		return FALSE;

	_r_queuedlock_acquireshared (&lock_state);

	ptr_decision = (PITEM_STATE_DECISION)_r_obj_findhashtablepointer (state_decisions, app_hash);

	if (ptr_decision)
	{
		is_present = TRUE;

		if (is_block)
			*is_block = ptr_decision->is_block;

		if (is_once)
			*is_once = ptr_decision->is_once;
	}

	_r_queuedlock_releaseshared (&lock_state);

	return is_present;
}

VOID _app_state_revokeapp (
	_In_ ULONG app_hash
)
{
	PITEM_STATE_DECISION ptr_decision;
	PR_ARRAY guids = NULL;

	if (!state_decisions)
		return;

	_r_queuedlock_acquireexclusive (&lock_state);

	ptr_decision = (PITEM_STATE_DECISION)_r_obj_findhashtablepointer (state_decisions, app_hash);

	if (ptr_decision)
	{
		// S4/P1-1: detach under the lock, destroy outside it
		guids = _app_state_detachlocked (ptr_decision);

		_r_obj_removehashtableitem (state_decisions, app_hash); // table derefs (frees)
	}

	_r_queuedlock_releaseexclusive (&lock_state);

	_app_state_destroyguids (guids);

	// S3 (2026-11-10): every revokeapp caller supersedes or cancels the
	// app's session state; the held-pending count accumulated under the
	// old state is stale the moment the state goes — drop it so the tray
	// never shows held connections for an app that lost its session
	// decision (covers app-delete, disable, and timer expiry for free)
	_app_state_releasepending (app_hash);
}

VOID _app_state_applyall (
	_In_opt_ HWND hwnd
)
{
	PITEM_APP ptr_app;
	PITEM_STATE_DECISION ptr_decision = NULL;
	ULONG_PTR enum_key = 0;

	if (!state_decisions || _r_obj_isempty2 (state_decisions))
		return;

	_r_queuedlock_acquireshared (&lock_state);

	while (_r_obj_enumhashtablepointer (state_decisions, (PVOID_PTR)&ptr_decision, NULL, &enum_key))
	{
		// "once" entries are exact-connection scoped and are not re-deployed
		// at rule-apply (their tuple is not stored; a re-deploy would have
		// to either drop them or silently upgrade them app-wide) — they
		// expire within minutes anyway (FR-04 "clean up after themselves")
		if (ptr_decision->is_once)
			continue;

		ptr_app = _app_getappitem (ptr_decision->app_hash);

		if (!ptr_app)
			continue;

		// re-deploy after the full apply wiped every provider filter
		_app_state_deploy (ptr_decision, ptr_app, NULL);

		_r_obj_dereference (ptr_app);
	}

	_r_queuedlock_releaseshared (&lock_state);
}

VOID _app_state_clearfilters (VOID)
{
	PITEM_STATE_DECISION ptr_decision = NULL;
	ULONG_PTR enum_key = 0;

	if (!state_decisions || _r_obj_isempty2 (state_decisions))
		return;

	_r_queuedlock_acquireexclusive (&lock_state);

	while (_r_obj_enumhashtablepointer (state_decisions, (PVOID_PTR)&ptr_decision, NULL, &enum_key))
	{
		// the provider teardown already deleted these filters — just drop
		// the stale guids; the decision records re-deploy on next install
		_r_obj_clearreference ((PVOID_PTR)&ptr_decision->guids);
	}

	_r_queuedlock_releaseexclusive (&lock_state);
}

VOID _app_state_holdpending (
	_In_ ULONG app_hash
)
{
	ULONG count;
	PVOID ptr_value;

	if (!state_held)
		return;

	_r_queuedlock_acquireexclusive (&lock_state);

	ptr_value = _r_obj_findhashtable (state_held, app_hash);

	count = ptr_value ? *(PULONG)ptr_value : 0;

	count += 1;

	_r_obj_addhashtableitem (state_held, app_hash, &count);

	_r_queuedlock_releaseexclusive (&lock_state);
}

VOID _app_state_releasepending (
	_In_ ULONG app_hash
)
{
	if (!state_held)
		return;

	_r_queuedlock_acquireexclusive (&lock_state);

	_r_obj_removehashtableitem (state_held, app_hash);

	_r_queuedlock_releaseexclusive (&lock_state);
}

// S3 (2026-11-10): clear every held-pending count. Held entries only
// accumulate while a prompt window is visible (single-flight: one prompt
// at a time), so once the prompt dies without a decision they are stale
// by definition — "N held for review" with no prompt open is a false
// promise; the underlying connections were already blocked and logged,
// and new holds re-accumulate under the next prompt
VOID _app_state_releaseallpending (
	VOID
)
{
	if (!state_held)
		return;

	_r_queuedlock_acquireexclusive (&lock_state);

	_r_obj_clearhashtable (state_held);

	_r_queuedlock_releaseexclusive (&lock_state);
}

ULONG _app_state_getheldtotal (VOID)
{
	ULONG count = 0;
	PVOID ptr_value = NULL;
	ULONG_PTR enum_key = 0;

	if (!state_held || _r_obj_isempty2 (state_held))
		return 0;

	_r_queuedlock_acquireshared (&lock_state);

	while (_r_obj_enumhashtable (state_held, &ptr_value, NULL, &enum_key))
		count += ptr_value ? *(PULONG)ptr_value : 0;

	_r_queuedlock_releaseshared (&lock_state);

	return count;
}


// P2-3b: collect every deployed session-decision filter GUID into the
// desired set (lock_state shared)
VOID _app_state_collectguids (
	_In_ PR_ARRAY desired
)
{
	PITEM_STATE_DECISION ptr_decision = NULL;
	ULONG_PTR enum_key = 0;

	_r_queuedlock_acquireshared (&lock_state);

	while (_r_obj_enumhashtablepointer (state_decisions, (PVOID_PTR)&ptr_decision, NULL, &enum_key))
	{
		if (!_r_obj_isempty2 (ptr_decision->guids))
			_r_obj_addarrayitems (desired, ptr_decision->guids->items, ptr_decision->guids->count);
	}

	_r_queuedlock_releaseshared (&lock_state);
}
