// simplewall (composite fork)
// Composite Phase 1 — Authenticode publisher rules (T004).
// FR-03/SEC-02/DEC-05: at prompt time the signer is captured through the
// existing WinVerifyTrust pipeline (helper.c _app_verifygetstring walk —
// signer SHA1 + self-signed status added there). "Always for publisher"
// stores a signer-hash anchor and materializes per-path PERMIT filters at
// the standard app-permit weight (FWW_APP) through the same
// provider/sublayer the upstream app filters use. Re-validation happens
// at prompt time (cache, per path+mtime), at the FileMonitor 10-minute
// loop and at rule-apply; a signer that no longer validates is revoked
// and logged (drop-out). Self-signed binaries never get a publisher
// binding (DEC-05).
//
// WFP layer stays exact-path materialization (vendor _r_str_match is
// user-space only). The anchor store is in-memory this round — sidecar
// persistence is T009 scope (DATA-01 keeps profile.xml untouched).
//
// Module-local exclusive lock (composite_audit.c precedent); WinVerifyTrust
// runs OUTSIDE the lock; no UI calls under the lock.

#include "global.h"
#include "composite_publisher.h"

#include "composite.h"

typedef struct _ITEM_PUBLISHER_PATH
{
	PR_STRING path; // canonical (original_path) binary path
	PR_STRING signer_hash; // hex SHA1 of the signer certificate (NULL when invalid)
	PR_STRING signer_name; // signer common name (informational)
	PR_ARRAY guids; // deployed per-path PERMIT filters (FWW_APP)

	LONG64 mtime; // file write-time at last stat
	LONG64 validated_mtime; // mtime at last validation (either outcome)

	ULONG path_hash; // _r_str_gethash(path, TRUE) == app_hash

	BOOLEAN is_valid; // last WinVerifyTrust outcome
	BOOLEAN is_selfsigned;
} ITEM_PUBLISHER_PATH, *PITEM_PUBLISHER_PATH;

typedef struct _ITEM_PUBLISHER
{
	PR_STRING signer_hash; // hex SHA1 anchor
	PR_STRING signer_name; // signer common name (informational)
} ITEM_PUBLISHER, *PITEM_PUBLISHER;

static R_QUEUED_LOCK lock_publisher = PR_QUEUED_LOCK_INIT;

static PR_HASHTABLE publisher_paths = NULL; // path_hash -> PITEM_PUBLISHER_PATH (pointer table owns the allocation ref)
static PR_HASHTABLE publisher_anchors = NULL; // hash-of-hex -> PITEM_PUBLISHER (pointer table owns the allocation ref)

// membership of a path in an anchor is derived: the path entry's
// signer_hash string equals the anchor's signer_hash string

static VOID NTAPI _app_publisher_dereferencepath (
	_In_ PVOID entry
)
{
	PITEM_PUBLISHER_PATH ptr_path = (PITEM_PUBLISHER_PATH)entry;

	if (ptr_path->path)
		_r_obj_clearreference ((PVOID_PTR)&ptr_path->path);

	if (ptr_path->signer_hash)
		_r_obj_clearreference ((PVOID_PTR)&ptr_path->signer_hash);

	if (ptr_path->signer_name)
		_r_obj_clearreference ((PVOID_PTR)&ptr_path->signer_name);

	if (ptr_path->guids)
		_r_obj_clearreference ((PVOID_PTR)&ptr_path->guids);
}

static VOID NTAPI _app_publisher_dereferenceanchor (
	_In_ PVOID entry
)
{
	PITEM_PUBLISHER ptr_anchor = (PITEM_PUBLISHER)entry;

	if (ptr_anchor->signer_hash)
		_r_obj_clearreference ((PVOID_PTR)&ptr_anchor->signer_hash);

	if (ptr_anchor->signer_name)
		_r_obj_clearreference ((PVOID_PTR)&ptr_anchor->signer_name);
}

VOID _app_publisher_initialize (VOID)
{
	publisher_paths = _r_obj_createhashtablepointer (0x04);
	publisher_anchors = _r_obj_createhashtablepointer (0x04);
}

// S4/P1-1 (2026-11-10): detach the path's live filter GUID list; the
// caller must destroy it OUTSIDE lock_publisher — _wfp_destroyfilters_array
// messages the UI (toolbar/statusbar), and a UI thread blocked on the same
// lock while the holder SendMessages it would hang (P1-1)
static PR_ARRAY _app_publisher_revokepath (
	_Inout_ PITEM_PUBLISHER_PATH ptr_path
)
{
	PR_ARRAY guids = ptr_path->guids;

	ptr_path->guids = NULL;

	return guids;
}

// destroy a detached (still-owned) GUID list outside lock_publisher;
// tolerates a gone engine handle like the previous in-lock path did
static VOID _app_publisher_destroyguids (
	_In_opt_ PR_ARRAY guids
)
{
	if (!guids)
		return;

	if (!_r_obj_isempty2 (guids) && _wfp_isfiltersinstalled ())
		_wfp_destroyfilters_array (_wfp_getenginehandle (), guids, DBG_ARG);

	_r_obj_dereference (guids);
}

static ULONG _app_publisher_anchork (
	_In_ PCR_STRINGREF signer_hash_sr
)
{
	return _r_str_gethash (signer_hash_sr, TRUE);
}

// TRUE when at least one path entry still carries this anchor's hash
static BOOLEAN _app_publisher_anchorhasmembers (
	_In_ PITEM_PUBLISHER ptr_anchor
)
{
	PITEM_PUBLISHER_PATH ptr_path = NULL;
	ULONG_PTR enum_key = 0;

	if (!publisher_paths)
		return FALSE;

	while (_r_obj_enumhashtablepointer (publisher_paths, (PVOID_PTR)&ptr_path, NULL, &enum_key))
	{
		if (ptr_path->signer_hash && _r_str_isequal (&ptr_path->signer_hash->sr, &ptr_anchor->signer_hash->sr, TRUE))
			return TRUE;
	}

	return FALSE;
}

// deploy (materialize) the PERMIT filters for a single bound path; the
// standard transaction pattern (mirrors _wfp_createappfilters: shared
// lock_transaction + tri-state _wfp_transact_start). Called with
// lock_publisher held (exclusive or shared) — WFP work only, no UI.
static BOOLEAN _app_publisher_deployentry (
	_Inout_ PITEM_PUBLISHER_PATH ptr_path,
	_In_opt_ PITEM_PUBLISHER ptr_anchor
)
{
	PR_STRING filter_name;
	HANDLE engine_handle;
	LPCGUID guid;
	ENUM_TRANSACT_STATE transact_state;
	BOOLEAN is_success;
	BOOLEAN is_locked = FALSE;
	BOOLEAN is_intransact;

	engine_handle = _wfp_getenginehandle ();

	if (!engine_handle || !_wfp_isfiltersinstalled ())
		return FALSE;

	if (!_r_obj_isempty2 (ptr_path->guids))
		return TRUE; // already materialized

	filter_name = _r_obj_concatstrings (2, L"Publisher: ", _r_obj_getstringordefault (ptr_anchor ? ptr_anchor->signer_name : NULL, ptr_path->path->buffer));

	if (_wfp_isfiltersapplying ())
	{
		is_intransact = TRUE;
	}
	else
	{
		_r_queuedlock_acquireshared (&lock_transaction);

		is_locked = TRUE;

		transact_state = _wfp_transact_start (engine_handle, DBG_ARG);

		if (transact_state == TXN_FAILED)
		{
			_r_log (LOG_LEVEL_WARNING, NULL, L"composite_publisher", L"transaction unavailable; materialization deferred to rule-apply", (LONG)transact_state);

			_r_queuedlock_releaseshared (&lock_transaction);

			_r_obj_dereference (filter_name);

			return FALSE;
		}

		is_intransact = (transact_state == TXN_IN_PROGRESS);
	}

	// exact-path PERMIT at the standard app-permit weight through the
	// same provider/sublayer as the upstream app filters; the WFP layer
	// stays exact-path (wildcard/pattern matching is user-space only).
	// Session-scoped (non-persistent) until T009 gives the anchor store
	// sidecar persistence — a persistent filter without a stored anchor
	// would be an unreasoned permit across reboots (SEC-02)
	_wfp_createrulefilter (
		engine_handle,
		DATA_APP_REGULAR, // filter metadata only; the condition resolves through path_hash (== app_hash)
		filter_name->buffer,
		ptr_path->path_hash,
		NULL,
		NULL,
		NULL,
		FWW_APP,
		FWP_ACTION_PERMIT,
		FWPCOMPOSITE_FLAG_SESSIONFILTER,
		ptr_path->guids
	);

	if (!is_intransact)
		_wfp_transact_commit (engine_handle, DBG_ARG);

	is_success = !_r_obj_isempty2 (ptr_path->guids);

	if (is_success)
	{
		for (ULONG_PTR i = 0; i < _r_obj_getarraysize (ptr_path->guids); i++)
		{
			guid = (LPCGUID)_r_obj_getarrayitem (ptr_path->guids, i);

			if (guid)
				_app_setfiltersecurity (engine_handle, guid, TRUE, DBG_ARG);
		}
	}

	if (is_locked)
		_r_queuedlock_releaseshared (&lock_transaction);

	_r_obj_dereference (filter_name);

	return is_success;
}

// verify a file and refresh its cache entry; WinVerifyTrust runs outside
// the module lock. Used at prompt time (pre-warm), tier3 (lazy binding),
// re-validation and binding. The refreshed entry is valid while the
// caller holds lock_publisher; callers re-lookup under the lock.
static VOID _app_publisher_querypath (
	_In_ PR_STRING path,
	_In_ BOOLEAN is_force_refresh
)
{
	PITEM_PUBLISHER_PATH ptr_path;
	PR_ARRAY detached_guids = NULL;
	PR_STRING signer_hash = NULL, signer_name = NULL;
	FILETIME write_time;
	LARGE_INTEGER mtime_li;
	HANDLE hfile = NULL;
	LONG64 mtime = 0;
	LONG status;
	BOOLEAN is_selfsigned = FALSE;
	BOOLEAN is_uptodate = FALSE;
	BOOLEAN was_materialized;

	if (!publisher_paths || _r_obj_isstringempty (path))
		return;

	if (!_app_isappvalidbinary (path))
		return;

	if (!NT_SUCCESS (_r_fs_openfile (&hfile, &path->sr, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, 0, FALSE)))
	{
		// SEC-02: a materialized binding whose binary can no longer be
		// opened (deleted/moved) must not survive — revoke and log
		_r_queuedlock_acquireexclusive (&lock_publisher);

		ptr_path = (PITEM_PUBLISHER_PATH)_r_obj_findhashtablepointer (publisher_paths, _r_str_gethash (&path->sr, TRUE));

		if (ptr_path && !_r_obj_isempty2 (ptr_path->guids))
		{
			detached_guids = _app_publisher_revokepath (ptr_path); // S4/P1-1: destroy outside the lock

			_r_log (LOG_LEVEL_WARNING, NULL, L"composite_publisher", ptr_path->path->buffer, (LONG)STATUS_OBJECT_NAME_NOT_FOUND);
		}

		_r_queuedlock_releaseexclusive (&lock_publisher);

		_app_publisher_destroyguids (detached_guids);

		return;
	}

	if (NT_SUCCESS (_r_fs_gettimestamp (hfile, NULL, NULL, &write_time)))
	{
		mtime_li.HighPart = write_time.dwHighDateTime;
		mtime_li.LowPart = write_time.dwLowDateTime;

		mtime = mtime_li.QuadPart;
	}

	// up-to-date check (per path+mtime cache, FR-03) — both outcomes are
	// cached, so an unsigned binary re-verifies only when its mtime moves
	_r_queuedlock_acquireshared (&lock_publisher);

	ptr_path = (PITEM_PUBLISHER_PATH)_r_obj_findhashtablepointer (publisher_paths, _r_str_gethash (&path->sr, TRUE));

	if (ptr_path && ptr_path->mtime == mtime && ptr_path->validated_mtime == mtime && !is_force_refresh)
		is_uptodate = TRUE;

	_r_queuedlock_releaseshared (&lock_publisher);

	if (!is_uptodate)
	{
		// full WinVerifyTrust pass (file + catalog fallback pipeline);
		// runs WITHOUT lock_publisher held
		status = _app_getfilepublisherinfo (path, hfile, &signer_hash, &signer_name, &is_selfsigned);

		if (status != ERROR_SUCCESS)
		{
			if (signer_hash)
				_r_obj_dereference (signer_hash);

			if (signer_name)
				_r_obj_dereference (signer_name);

			signer_hash = NULL;
			signer_name = NULL;
		}

		_r_queuedlock_acquireexclusive (&lock_publisher);

		ptr_path = (PITEM_PUBLISHER_PATH)_r_obj_findhashtablepointer (publisher_paths, _r_str_gethash (&path->sr, TRUE));

		if (!ptr_path)
		{
			ptr_path = (PITEM_PUBLISHER_PATH)_r_obj_allocate (sizeof (ITEM_PUBLISHER_PATH), &_app_publisher_dereferencepath);

			ptr_path->path = _r_obj_createstring2 (&path->sr);
			ptr_path->path_hash = _r_str_gethash (&path->sr, TRUE);
			ptr_path->guids = _r_obj_createarray (sizeof (GUID), 0x04, NULL);

			// the allocation reference becomes the table's ownership
			// reference (vendor pointer-table contract, see apps_table)
			_r_obj_addhashtablepointer (publisher_paths, ptr_path->path_hash, ptr_path);
		}

		was_materialized = !_r_obj_isempty2 (ptr_path->guids);

		ptr_path->mtime = mtime;
		ptr_path->is_selfsigned = is_selfsigned;

		_r_obj_movereference ((PVOID_PTR)&ptr_path->signer_hash, signer_hash);
		_r_obj_movereference ((PVOID_PTR)&ptr_path->signer_name, signer_name);

		ptr_path->is_valid = (status == ERROR_SUCCESS && ptr_path->signer_hash != NULL);
		ptr_path->validated_mtime = mtime;

		// drop-out (FR-03/SEC-02): a previously materialized path whose
		// signer no longer validates (or turned self-signed) is revoked
		// and logged
		if (was_materialized && (!ptr_path->is_valid || ptr_path->is_selfsigned))
		{
			detached_guids = _app_publisher_revokepath (ptr_path); // S4/P1-1: destroy outside the lock

			_r_log (LOG_LEVEL_WARNING, NULL, L"composite_publisher", ptr_path->path->buffer, (LONG)status);
		}

		_r_queuedlock_releaseexclusive (&lock_publisher);

		_app_publisher_destroyguids (detached_guids);
	}

	if (hfile)
		NtClose (hfile);
}

BOOLEAN _app_publisher_capturefile (
	_In_ PR_STRING path
)
{
	if (!_r_config_getboolean (COMPOSITE_CONFIG_PUBLISHER, TRUE, NULL))
		return FALSE;

	// the cache refresh itself is the point
	_app_publisher_querypath (path, FALSE);

	return TRUE;
}

BOOLEAN _app_publisher_isavailable (
	_In_ ULONG app_hash
)
{
	PITEM_APP ptr_app;
	PITEM_PUBLISHER_PATH ptr_path;
	PR_STRING path;
	BOOLEAN is_available = FALSE;

	if (!_r_config_getboolean (COMPOSITE_CONFIG_PUBLISHER, TRUE, NULL))
		return FALSE;

	ptr_app = _app_getappitem (app_hash);

	if (!ptr_app)
		return FALSE;

	// publisher binding is a plain-binary concept (DEC-05); services/uwp
	// packages are keyed by security descriptor/package sid, not path
	if (ptr_app->type == DATA_APP_SERVICE || ptr_app->type == DATA_APP_UWP)
	{
		_r_obj_dereference (ptr_app);

		return FALSE;
	}

	path = ptr_app->real_path ? ptr_app->real_path : ptr_app->original_path;

	_r_obj_dereference (ptr_app);

	if (_r_obj_isstringempty (path) || !_app_isappvalidbinary (path))
		return FALSE;

	// refine the cache (cheap when the path+mtime is unchanged; a rare
	// synchronous WinVerifyTrust when the pre-warm lost the race)
	_app_publisher_querypath (path, FALSE);

	_r_queuedlock_acquireshared (&lock_publisher);

	ptr_path = (PITEM_PUBLISHER_PATH)_r_obj_findhashtablepointer (publisher_paths, _r_str_gethash (&path->sr, TRUE));

	is_available = (ptr_path && ptr_path->is_valid && !ptr_path->is_selfsigned && ptr_path->signer_hash != NULL);

	_r_queuedlock_releaseshared (&lock_publisher);

	return is_available;
}

BOOLEAN _app_publisher_ismaterialized (
	_In_ LPCWSTR path
)
{
	PITEM_PUBLISHER_PATH ptr_path;
	R_STRINGREF path_sr;
	BOOLEAN is_materialized = FALSE;

	if (!publisher_paths || !path || !*path)
		return FALSE;

	_r_obj_initializestringref (&path_sr, path);

	_r_queuedlock_acquireshared (&lock_publisher);

	ptr_path = (PITEM_PUBLISHER_PATH)_r_obj_findhashtablepointer (publisher_paths, _r_str_gethash (&path_sr, TRUE));

	is_materialized = (ptr_path && !_r_obj_isempty2 (ptr_path->guids));

	_r_queuedlock_releaseshared (&lock_publisher);

	return is_materialized;
}

BOOLEAN _app_publisher_istiercovered (
	_In_ PITEM_APP ptr_app
)
{
	PITEM_PUBLISHER ptr_anchor;
	PITEM_PUBLISHER_PATH ptr_path;
	PR_STRING path;
	BOOLEAN is_covered = FALSE;

	if (!_r_config_getboolean (COMPOSITE_CONFIG_PUBLISHER, TRUE, NULL))
		return FALSE;

	if (!ptr_app || ptr_app->type == DATA_APP_SERVICE || ptr_app->type == DATA_APP_UWP)
		return FALSE;

	path = ptr_app->real_path ? ptr_app->real_path : ptr_app->original_path;

	if (_r_obj_isstringempty (path) || !_app_isappvalidbinary (path))
		return FALSE;

	// refresh the per-path+mtime signer cache (cheap when unchanged)
	_app_publisher_querypath (path, FALSE);

	_r_queuedlock_acquireexclusive (&lock_publisher);

	ptr_path = (PITEM_PUBLISHER_PATH)_r_obj_findhashtablepointer (publisher_paths, _r_str_gethash (&path->sr, TRUE));

	if (!ptr_path || !ptr_path->is_valid || ptr_path->is_selfsigned || !ptr_path->signer_hash)
	{
		_r_queuedlock_releaseexclusive (&lock_publisher);

		return FALSE;
	}

	// an anchor must exist for this signer (user-bound publisher); a
	// mere valid signature is never coverage
	ptr_anchor = (PITEM_PUBLISHER)_r_obj_findhashtablepointer (publisher_anchors, _app_publisher_anchork (&ptr_path->signer_hash->sr));

	if (!ptr_anchor)
	{
		_r_queuedlock_releaseexclusive (&lock_publisher);

		return FALSE;
	}

	if (!_r_obj_isempty2 (ptr_path->guids))
	{
		// already materialized (T003 tier3 fast outcome)
		is_covered = TRUE;
	}
	else
	{
		// FR-03 lazy binding: a binary at a (new) path whose signer
		// matches a stored anchor is permitted and logged, not prompted
		if (_app_publisher_deployentry (ptr_path, ptr_anchor))
		{
			is_covered = TRUE;

			_r_log (LOG_LEVEL_INFO, NULL, L"composite_publisher", ptr_path->path->buffer, (LONG)ERROR_SUCCESS);
		}
	}

	_r_queuedlock_releaseexclusive (&lock_publisher);

	return is_covered;
}

BOOLEAN _app_publisher_bind (
	_In_opt_ HWND hwnd,
	_In_ PITEM_APP ptr_app
)
{
	PITEM_PUBLISHER ptr_anchor;
	PITEM_PUBLISHER_PATH ptr_path;
	PR_STRING path;
	BOOLEAN is_success = FALSE;

	if (!_r_config_getboolean (COMPOSITE_CONFIG_PUBLISHER, TRUE, NULL))
		return FALSE;

	if (!ptr_app || ptr_app->type == DATA_APP_SERVICE || ptr_app->type == DATA_APP_UWP)
		return FALSE;

	path = ptr_app->real_path ? ptr_app->real_path : ptr_app->original_path;

	if (_r_obj_isstringempty (path) || !_app_isappvalidbinary (path))
		return FALSE;

	// fresh validation for the binding itself (SEC-02: bind only to
	// WinVerifyTrust-valid chains, at every binding point)
	_app_publisher_querypath (path, TRUE);

	_r_queuedlock_acquireexclusive (&lock_publisher);

	ptr_path = (PITEM_PUBLISHER_PATH)_r_obj_findhashtablepointer (publisher_paths, _r_str_gethash (&path->sr, TRUE));

	if (!ptr_path || !ptr_path->is_valid || ptr_path->is_selfsigned || !ptr_path->signer_hash)
	{
		// self-signed (or unsigned) binaries never get a publisher binding
		_r_queuedlock_releaseexclusive (&lock_publisher);

		return FALSE;
	}

	ptr_anchor = (PITEM_PUBLISHER)_r_obj_findhashtablepointer (publisher_anchors, _app_publisher_anchork (&ptr_path->signer_hash->sr));

	if (!ptr_anchor)
	{
		ptr_anchor = (PITEM_PUBLISHER)_r_obj_allocate (sizeof (ITEM_PUBLISHER), &_app_publisher_dereferenceanchor);

		ptr_anchor->signer_hash = _r_obj_reference (ptr_path->signer_hash);
		ptr_anchor->signer_name = ptr_path->signer_name ? _r_obj_reference (ptr_path->signer_name) : NULL;

		// the allocation reference becomes the table's ownership reference
		_r_obj_addhashtablepointer (publisher_anchors, _app_publisher_anchork (&ptr_path->signer_hash->sr), ptr_anchor);
	}

	// materialize this path (other members (re-)materialize at
	// rule-apply and lazily at connection)
	is_success = _app_publisher_deployentry (ptr_path, ptr_anchor);

	_r_log (
		LOG_LEVEL_INFO,
		NULL,
		L"composite_publisher",
		ptr_path->path->buffer,
		is_success ? (LONG)ERROR_SUCCESS : (LONG)E_FAIL
	);

	_r_queuedlock_releaseexclusive (&lock_publisher);

	return is_success;
}

VOID _app_publisher_revalidate (VOID)
{
	PITEM_PUBLISHER_PATH ptr_path = NULL;
	PR_LIST path_list;
	PR_STRING path;
	ULONG_PTR enum_key = 0;

	if (!publisher_paths || _r_obj_isempty2 (publisher_paths))
		return;

	// snapshot the materialized paths under the lock, then re-verify
	// outside it (WinVerifyTrust must not run under lock_publisher)
	path_list = _r_obj_createlist (0x02, &_r_obj_dereference);

	_r_queuedlock_acquireshared (&lock_publisher);

	while (_r_obj_enumhashtablepointer (publisher_paths, (PVOID_PTR)&ptr_path, NULL, &enum_key))
	{
		if (!_r_obj_isempty2 (ptr_path->guids))
			_r_obj_addlistitem (path_list, _r_obj_reference (ptr_path->path), NULL);
	}

	_r_queuedlock_releaseshared (&lock_publisher);

	while (!_r_obj_isempty2 (path_list))
	{
		path = (PR_STRING)_r_obj_getlistitem (path_list, 0);

		_app_publisher_querypath (path, FALSE); // mtime unchanged → no re-verify; changed → re-verify (+ revoke on failure)

		_r_obj_removelistitem (path_list, 0);
	}

	_r_obj_dereference (path_list);
}

VOID _app_publisher_applyall (
	_In_opt_ HWND hwnd
)
{
	PITEM_PUBLISHER ptr_anchor = NULL;
	PITEM_PUBLISHER_PATH ptr_path = NULL;
	ULONG_PTR anchor_key = 0, path_key = 0;

	if (!publisher_anchors || _r_obj_isempty2 (publisher_anchors))
		return;

	// SEC-02: publisher rules bind only to WinVerifyTrust-valid chains at
	// every materialization AND rule-apply point
	_app_publisher_revalidate ();

	_r_queuedlock_acquireexclusive (&lock_publisher);

	while (_r_obj_enumhashtablepointer (publisher_anchors, (PVOID_PTR)&ptr_anchor, NULL, &anchor_key))
	{
		path_key = 0;

		while (_r_obj_enumhashtablepointer (publisher_paths, (PVOID_PTR)&ptr_path, NULL, &path_key))
		{
			if (!ptr_path->is_valid || ptr_path->is_selfsigned || !ptr_path->signer_hash)
				continue;

			if (!_r_str_isequal (&ptr_path->signer_hash->sr, &ptr_anchor->signer_hash->sr, TRUE))
				continue;

			_app_publisher_deployentry (ptr_path, ptr_anchor);
		}
	}

	_r_queuedlock_releaseexclusive (&lock_publisher);

	// drop anchors whose membership vanished (separate pass — removing
	// while enumerating the same table is not safe with the array-backed
	// vendor hashtable)
	_r_queuedlock_acquireexclusive (&lock_publisher);

	anchor_key = 0;

	while (_r_obj_enumhashtablepointer (publisher_anchors, (PVOID_PTR)&ptr_anchor, NULL, &anchor_key))
	{
		if (!_app_publisher_anchorhasmembers (ptr_anchor))
			_r_obj_removehashtableitem (publisher_anchors, _app_publisher_anchork (&ptr_anchor->signer_hash->sr));
	}

	_r_queuedlock_releaseexclusive (&lock_publisher);
}

VOID _app_publisher_clearfilters (VOID)
{
	PITEM_PUBLISHER_PATH ptr_path = NULL;
	ULONG_PTR enum_key = 0;

	if (!publisher_paths || _r_obj_isempty2 (publisher_paths))
		return;

	_r_queuedlock_acquireexclusive (&lock_publisher);

	while (_r_obj_enumhashtablepointer (publisher_paths, (PVOID_PTR)&ptr_path, NULL, &enum_key))
	{
		// the provider teardown already deleted these filters — just drop
		// the stale guids; valid bindings re-materialize at rule-apply
		_r_obj_clearreference ((PVOID_PTR)&ptr_path->guids);
	}

	_r_queuedlock_releaseexclusive (&lock_publisher);
}

VOID _app_publisher_uninitialize (VOID)
{
	PITEM_PUBLISHER_PATH ptr_path = NULL;
	ULONG_PTR enum_key = 0;

	_r_queuedlock_acquireexclusive (&lock_publisher);

	if (publisher_paths)
	{
		while (_r_obj_enumhashtablepointer (publisher_paths, (PVOID_PTR)&ptr_path, NULL, &enum_key))
			_app_publisher_revokepath (ptr_path);

		_r_obj_clearhashtable (publisher_paths); // derefs (and frees) every entry
	}

	if (publisher_anchors)
		_r_obj_clearhashtable (publisher_anchors);

	_r_queuedlock_releaseexclusive (&lock_publisher);
}
