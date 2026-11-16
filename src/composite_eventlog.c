// simplewall (composite fork)
// Composite Phase 1 - Security-audit event prompt pipeline (T002, FR-01/DEC-03).
//
// Subscribes to the machine-wide "Security" channel for EventID 5157
// (Filtering Platform Connection failure audits, success auditing stays
// off - 5156 is a machine-wide flood) and feeds the produced blocks into
// the EXISTING log pipeline: events are rendered, mapped onto PITEM_LOG
// and queued on log_queue, so admission/auto-add, notifications, the UI
// log and the file log all keep behaving exactly as for WFP-sourced
// events (_app_logthread owns the admission gates, FR-01).
//
// Health/degradation (RSK-08, T002 scope): a failed subscribe, a delivery
// error or a missing audit subcategory marks the prompt pipeline degraded;
// the UI surfaces it (controls.c) and the WFP FwpmNetEventSubscribe
// pipeline remains the fallback the whole time. This is separate from the
// enforcement-degraded state (_wfp_degraded_mark resets every apply).
//
// wevtapi is resolved dynamically (same pattern as _wfp_logsubscribe,
// log.c:464-512) for OS-degradation parity; the module is never unloaded.
//
// No UI calls from the callback thread - only log_queue items (DEC-03).

#include "global.h"
#include "composite_eventlog.h"
#include "composite_audit.h"

#include <winevt.h>

#define COMPOSITE_EVENTLOG_CHANNEL L"Security"
#define COMPOSITE_EVENTLOG_QUERY L"*[System[(EventID=5157)]]"
#define COMPOSITE_EVENTLOG_DEDUP_MS 2000 // light port-merge dedup (T002 scope, full FR-05 in T006)

// config gate (single source for the start hook)
#define COMPOSITE_CONFIG_EVENTLOG L"IsCompositeEventLogEnabled"

// typed function pointers for the dynamically resolved wevtapi imports
// (signatures mirror winevt.h; EVT_SUBSCRIBE_CALLBACK is the exact SDK
// callback type — note EvtSubscribe itself gets its own EVT_SUBSCRIBE_FN)
typedef BOOL (WINAPI *EVT_CLOSE_FN) (EVT_HANDLE);
typedef BOOL (WINAPI *EVT_RENDER_FN) (EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD);
typedef EVT_HANDLE (WINAPI *EVT_CREATERENDERCONTEXT_FN) (DWORD, LPCWSTR *, DWORD);
typedef EVT_HANDLE (WINAPI *EVT_SUBSCRIBE_FN) (EVT_HANDLE, HANDLE, LPCWSTR, LPCWSTR, EVT_HANDLE, PVOID, EVT_SUBSCRIBE_CALLBACK, DWORD);

// dynamic wevtapi resolve - binds EvtSubscribe/EvtClose/EvtRender/EvtCreateRenderContext
static HANDLE wevtapi_module = NULL;
static NTSTATUS resolve_status = STATUS_PROCEDURE_NOT_FOUND; // written once under init_once

static EVT_SUBSCRIBE_FN _EvtSubscribe = NULL;
static EVT_CLOSE_FN _EvtClose = NULL;
static EVT_RENDER_FN _EvtRender = NULL;
static EVT_CREATERENDERCONTEXT_FN _EvtCreateRenderContext = NULL;

// render context: value paths in EventData render order (must match the
// _app_eventlog_processevent indexing). 5157 EventData has no PID field.
static LPCWSTR event_value_paths[] =
{
	L"Event/EventData/Application",  // 0: NT device path of the local app
	L"Event/EventData/SourceAddress", // 1: local endpoint (string)
	L"Event/EventData/SourcePort",  // 2
	L"Event/EventData/DestAddress", // 3: remote endpoint (string)
	L"Event/EventData/DestPort",    // 4
	L"Event/EventData/Protocol",    // 5
	L"Event/EventData/FilterRTID",  // 6
	L"Event/EventData/LayerName",   // 7: may be localized - do not parse, display only
	L"Event/EventData/LayerRTID",   // 8: culture-invariant layer id
};

#define EVENT_VALUE_COUNT RTL_NUMBER_OF (event_value_paths)

static EVT_HANDLE render_context = NULL; // created once, process-lifetime (RSK-01: avoids a stop-time race with in-flight callbacks; mirrors the never-unload wevtapi pattern)

static EVT_HANDLE subscription_handle = NULL; // live EvtSubscribe handle, guarded by lock_eventlog

static R_QUEUED_LOCK lock_eventlog = PR_QUEUED_LOCK_INIT; // guards subscription state

static volatile BOOLEAN is_prompt_started = FALSE; // composite feature active this session (start attempted)
static volatile BOOLEAN is_subscribed = FALSE; // plain volatile BOOLEAN read/write, matches is_enforcementdegraded precedent
static volatile BOOLEAN is_promptsdegraded = FALSE;

// FR-05 single-flight window: owned here so the prompt state has a single
// home; the full in-flight interlock lands in T006 (T002 ships light dedup only)
static volatile LONG is_prompt_active = 0;

// light port-merge dedup (T002): same event key inside 2 s is dropped
static R_QUEUED_LOCK lock_dedup = PR_QUEUED_LOCK_INIT;
static ULONG64 last_event_tick = 0;
static ULONG64 last_event_hash = 0;

static NTSTATUS _app_eventlog_resolvewevtapi (VOID)
{
	static R_INITONCE init_once = PR_INITONCE_INIT;
	NTSTATUS status;

	if (_r_initonce_begin (&init_once))
	{
		status = _r_sys_loadlibrary2 (&wevtapi_module, L"wevtapi.dll", 0);

		if (NT_SUCCESS (status))
		{
			_EvtSubscribe = (EVT_SUBSCRIBE_FN)_r_sys_getprocaddress (wevtapi_module, "EvtSubscribe", 0);
			_EvtClose = (EVT_CLOSE_FN)_r_sys_getprocaddress (wevtapi_module, "EvtClose", 0);
			_EvtRender = (EVT_RENDER_FN)_r_sys_getprocaddress (wevtapi_module, "EvtRender", 0);
			_EvtCreateRenderContext = (EVT_CREATERENDERCONTEXT_FN)_r_sys_getprocaddress (wevtapi_module, "EvtCreateRenderContext", 0);

			if (!(_EvtSubscribe && _EvtClose && _EvtRender && _EvtCreateRenderContext))
				status = STATUS_PROCEDURE_NOT_FOUND;
		}

		// never unload the module (parity with fwpuclnt in _wfp_logsubscribe)

		resolve_status = status;

		_r_initonce_end (&init_once);
	}

	return resolve_status;
}

static ULONG64 _app_eventlog_mixhash (ULONG64 value)
{
	value ^= value >> 33;
	value *= 0xff51afd7ed558ccdULL;
	value ^= value >> 33;
	value *= 0xc4ceb9fe1a85ec53ULL;
	value ^= value >> 33;

	return value;
}

static ULONG64 _app_eventlog_geteventkey (_In_ PITEM_LOG ptr_log)
{
	ULONG64 hash;

	// dedup key: app + destination endpoint + protocol + family
	hash = _app_eventlog_mixhash ((ULONG64)ptr_log->app_hash);
	hash = _app_eventlog_mixhash (hash ^ ((ULONG64)ptr_log->remote_port << 16));
	hash = _app_eventlog_mixhash (hash ^ (ULONG64)ptr_log->protocol);
	hash = _app_eventlog_mixhash (hash ^ (ULONG64)ptr_log->af);

	if (ptr_log->af == AF_INET)
	{
		hash = _app_eventlog_mixhash (hash ^ (ULONG64)ptr_log->remote_addr.S_un.S_addr);
	}
	else
	{
		for (ULONG i = 0; i < RTL_NUMBER_OF (ptr_log->remote_addr6.u.Byte); i++)
			hash = _app_eventlog_mixhash (hash ^ (ULONG64)ptr_log->remote_addr6.u.Byte[i]);
	}

	return hash;
}

static LPCWSTR _app_eventlog_getstringvalue (
	_In_opt_ PEVT_VARIANT variant
)
{
	if (!variant || variant->Type != EvtVarTypeString)
		return NULL;

	return variant->StringVal;
}

static UINT64 _app_eventlog_getnumbervalue (
	_In_opt_ PEVT_VARIANT variant
)
{
	if (!variant)
		return 0;

	switch (variant->Type)
	{
		case EvtVarTypeString:
		{
			return _wcstoui64 (variant->StringVal, NULL, 10);
		}

		case EvtVarTypeUInt16:
		{
			return (UINT64)variant->UInt16Val;
		}

		case EvtVarTypeUInt32:
		{
			return (UINT64)variant->UInt32Val;
		}

		case EvtVarTypeUInt64:
		{
			return variant->UInt64Val;
		}
	}

	return 0;
}

static BOOLEAN _app_eventlog_rendervalues (
	_In_ EVT_HANDLE event,
	_Outptr_result_buffer_ (*out_count) PEVT_VARIANT *out_values,
	_Out_ PDWORD out_count
)
{
	PEVT_VARIANT values;
	DWORD buffer_size;
	DWORD used = 0;
	DWORD count = 0;
	BOOLEAN is_success = FALSE;

	*out_values = NULL;
	*out_count = 0;

	// grow-loop: query the required buffer size first
	buffer_size = 0;

	if (_EvtRender (render_context, event, EvtRenderEventValues, buffer_size, NULL, &used, &count))
		return FALSE; // a NULL buffer never renders values

	if (GetLastError () != ERROR_INSUFFICIENT_BUFFER)
		return FALSE;

	buffer_size = used;

	values = (PEVT_VARIANT)_r_mem_allocate (buffer_size);

	if (_EvtRender (render_context, event, EvtRenderEventValues, buffer_size, values, &used, &count))
	{
		*out_values = values;
		*out_count = count;

		is_success = TRUE;
	}
	else
	{
		_r_mem_free (values);
	}

	return is_success;
}

static VOID _app_eventlog_processevent (
	_In_ EVT_HANDLE event
)
{
	PITEM_LOG ptr_log;
	PEVT_VARIANT values = NULL;
	PR_STRING nt_path;
	LPCWSTR app_value;
	LPCWSTR source_value;
	LPCWSTR dest_value;
	LPCWSTR layer_value;
	WCHAR buffer[64];
	UINT64 filter_rtid;
	UINT64 event_key;
	ULONG64 current_tick;
	ULONG source_port;
	ULONG dest_port;
	ULONG protocol;
	ULONG layer_rtid;
	DWORD value_count = 0;
	ADDRESS_FAMILY af;

	if (!_app_eventlog_rendervalues (event, &values, &value_count))
		return;

	if (value_count < EVENT_VALUE_COUNT)
	{
		_r_mem_free (values);
		return;
	}

	app_value = _app_eventlog_getstringvalue (&values[0]);
	source_value = _app_eventlog_getstringvalue (&values[1]);
	dest_value = _app_eventlog_getstringvalue (&values[3]);

	source_port = (ULONG)_app_eventlog_getnumbervalue (&values[2]);
	dest_port = (ULONG)_app_eventlog_getnumbervalue (&values[4]);
	protocol = (ULONG)_app_eventlog_getnumbervalue (&values[5]);

	filter_rtid = _app_eventlog_getnumbervalue (&values[6]);
	layer_value = _app_eventlog_getstringvalue (&values[7]); // display only (may be localized or absent)
	layer_rtid = (ULONG)_app_eventlog_getnumbervalue (&values[8]);
	BOOLEAN is_inbound;

	if (!app_value || !source_value || !dest_value || !*app_value || !*source_value || !*dest_value)
	{
		_r_mem_free (values);
		return;
	}

	// build the shared log object (PITEM_LOG contract, FR-01): everything
	// below mirrors what _wfp_logcallback fills for WFP-sourced events
	ptr_log = (PITEM_LOG)_r_obj_allocate (sizeof (ITEM_LOG), &_app_dereferencelog);

	RtlZeroMemory (ptr_log, sizeof (ITEM_LOG));

	// 5157 reports both endpoints as strings - parse into the binary form
	// the shared pipeline expects (InetPtonW fills network byte order)
	// 5157 LayerRTID: 44/46 = recv/accept (inbound: DestAddress is LOCAL,
	// SourceAddress is the remote peer); 48/50 = connect (outbound)
	is_inbound = (layer_rtid == 44 || layer_rtid == 46);

	ptr_log->direction = is_inbound ? FWP_DIRECTION_INBOUND : FWP_DIRECTION_OUTBOUND;

	if (InetPtonW (AF_INET, is_inbound ? source_value : dest_value, &ptr_log->remote_addr) == 1)
	{
		af = AF_INET;

		if (InetPtonW (AF_INET, is_inbound ? dest_value : source_value, &ptr_log->local_addr) != 1)
		{
			_r_obj_dereference (ptr_log);
			_r_mem_free (values);
			return;
		}

		// indicates whether the packet originated from (or was heading to) the loopback adapter
		ptr_log->is_loopback = (BOOLEAN)(IN4_IS_ADDR_LOOPBACK (&ptr_log->remote_addr) && IN4_IS_ADDR_LOOPBACK (&ptr_log->local_addr));
	}
	else if (InetPtonW (AF_INET6, is_inbound ? source_value : dest_value, &ptr_log->remote_addr6) == 1)
	{
		af = AF_INET6;

		if (InetPtonW (AF_INET6, is_inbound ? dest_value : source_value, &ptr_log->local_addr6) != 1)
		{
			_r_obj_dereference (ptr_log);
			_r_mem_free (values);
			return;
		}

		ptr_log->is_loopback = (BOOLEAN)(IN6_IS_ADDR_LOOPBACK (&ptr_log->remote_addr6) && IN6_IS_ADDR_LOOPBACK (&ptr_log->local_addr6));
	}
	else
	{
		_r_obj_dereference (ptr_log);
		_r_mem_free (values);
		return;
	}

	// path: 5157 "Application" is an NT device path - convert into win32
	nt_path = _r_obj_createstring (app_value);

	ptr_log->path = _r_path_dospathfromnt (&nt_path->sr); // maybenull

	_r_obj_dereference (nt_path);

	if (ptr_log->path)
		ptr_log->app_hash = _r_str_gethash (&ptr_log->path->sr, TRUE); // case-insensitive (matches _wfp_logcallback)

	ptr_log->timestamp = _r_unixtime_now ();
	ptr_log->af = af;

	// ports and protocol (5157: Application -> DestAddress, treat as OUTBOUND)
	ptr_log->remote_port = (UINT16)dest_port;
	ptr_log->local_port = (UINT16)source_port;
	ptr_log->protocol = (UINT8)protocol;

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"<unknown protocol> (% " TEXT (PRIu8) L")", ptr_log->protocol);

	ptr_log->protocol_str = _r_obj_createstring (_app_db_getprotoname (ptr_log->protocol, ptr_log->af, buffer));

	ptr_log->filter_id = filter_rtid;

	ptr_log->filter_name = _r_obj_createstring (L"Windows Filtering Platform (audit)");

	// culture-invariant layer id (DEC-03) - the localized LayerName string is
	// deliberately not used; map the well-known ALE auth layers only
	switch (layer_rtid)
	{
		case 44:
		{
			layer_value = L"ALE Auth Receive Accept V4";
			break;
		}

		case 46:
		{
			layer_value = L"ALE Auth Receive Accept V6";
			break;
		}

		case 48:
		{
			layer_value = L"ALE Auth Connect V4";
			break;
		}

		case 50:
		{
			layer_value = L"ALE Auth Connect V6";
			break;
		}

		default:
		{
			layer_value = L"";
			break;
		}
	}

	ptr_log->layer_name = _r_obj_createstring (layer_value);

	// composite source flags: block, foreign provider, audit feed (FR-01);
	// is_blocklist/is_custom/is_system stay FALSE (zeroed)
	ptr_log->is_composite = TRUE;
	ptr_log->is_myprovider = FALSE;
	ptr_log->is_allow = FALSE;

	_r_mem_free (values);

	// light port-merge dedup (T002 scope; full FR-05 single-flight in T006)
	event_key = _app_eventlog_geteventkey (ptr_log);
	current_tick = GetTickCount64 ();

	_r_queuedlock_acquireexclusive (&lock_dedup);

	if (last_event_hash == event_key && (current_tick - last_event_tick) <= COMPOSITE_EVENTLOG_DEDUP_MS)
	{
		_r_queuedlock_releaseexclusive (&lock_dedup);

		_r_obj_dereference (ptr_log); // duplicate inside the window - drop
		return;
	}

	last_event_hash = event_key;
	last_event_tick = current_tick;

	_r_queuedlock_releaseexclusive (&lock_dedup);

	// the queue takes ownership of our initial reference; _app_logthread
	// owns admission/auto-add/notifications/logs from here (FR-01)
	_r_workqueue_queueitem (&log_queue, &_app_logthread, ptr_log);
}

static DWORD WINAPI _app_eventlog_callback (
	_In_ EVT_SUBSCRIBE_NOTIFY_ACTION action,
	_In_opt_ PVOID context,
	_In_ EVT_HANDLE event
)
{
	if (action == EvtSubscribeActionError)
	{
		// RSK-08: the 5157 feed is no longer trustworthy - surface the
		// degraded state; the WFP FwpmNetEventSubscribe pipeline keeps
		// running as the fallback the whole time
		is_promptsdegraded = TRUE;

		_r_log (LOG_LEVEL_WARNING, NULL, L"EvtSubscribe", L"composite 5157 delivery error", (NTSTATUS)(ULONG_PTR)(ULONG_PTR)event);

		return ERROR_SUCCESS;
	}

	if (action != EvtSubscribeActionDeliver)
		return ERROR_SUCCESS;

	_app_eventlog_processevent (event);

	return ERROR_SUCCESS;
}

static BOOLEAN _app_eventlog_createrendercontext (VOID)
{
	// created once, never closed (RSK-01: a stop-time EvtClose could race an
	// in-flight callback still rendering; process-lifetime mirrors the
	// never-unload wevtapi pattern)
	if (render_context)
		return TRUE;

	render_context = _EvtCreateRenderContext (EVENT_VALUE_COUNT, event_value_paths, 0 /* EvtRenderContextValues */);

	return (render_context != NULL);
}

NTSTATUS _app_eventlog_start (
	_In_ HWND hwnd
)
{
	EVT_HANDLE new_handle;
	NTSTATUS status;

	status = _app_eventlog_resolvewevtapi ();

	if (!NT_SUCCESS (status))
	{
		is_prompt_started = TRUE; // feature is on this session...
		is_promptsdegraded = TRUE; // ...but the Security-channel feed is unavailable (RSK-08)

		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_eventlog_start", L"wevtapi.dll", status);

		return status;
	}

	_r_queuedlock_acquireexclusive (&lock_eventlog);

	if (subscription_handle)
	{
		// already subscribed (single-flight; start runs on every apply)
		_r_queuedlock_releaseexclusive (&lock_eventlog);

		is_prompt_started = TRUE;

		return STATUS_SUCCESS;
	}

	if (!_app_eventlog_createrendercontext ())
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());

		is_prompt_started = TRUE;
		is_promptsdegraded = TRUE; // RSK-08

		_r_queuedlock_releaseexclusive (&lock_eventlog);

		_r_log (LOG_LEVEL_WARNING, NULL, L"EvtCreateRenderContext", COMPOSITE_EVENTLOG_CHANNEL, status);

		return status;
	}

	// push model: Session = NULL, SignalEvent = NULL (must be NULL with a
	// callback), Bookmark = NULL, future events only
	new_handle = _EvtSubscribe (NULL, NULL, COMPOSITE_EVENTLOG_CHANNEL, COMPOSITE_EVENTLOG_QUERY, NULL, NULL, _app_eventlog_callback, EvtSubscribeToFutureEvents);

	if (!new_handle)
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());

		is_prompt_started = TRUE; // feature is on this session...
		is_promptsdegraded = TRUE; // ...but the Security-channel feed is unavailable (RSK-08)

		_r_queuedlock_releaseexclusive (&lock_eventlog);

		if (hwnd)
		{
			_r_show_errormessage (hwnd, L"Could not subscribe to the \"Security\" channel (5157 audit feed). The WFP log pipeline remains active!", NULL, status, ET_WINDOWS);
		}
		else
		{
			_r_log (LOG_LEVEL_WARNING, NULL, L"EvtSubscribe", COMPOSITE_EVENTLOG_CHANNEL, status);
		}

		return status;
	}

	subscription_handle = new_handle;

	is_prompt_started = TRUE;
	is_subscribed = TRUE;
	is_promptsdegraded = FALSE;

	// DEC-03: the feed is only as good as the audit subcategory behind it -
	// simple health guard at start (T002 scope)
	if (!_app_audit_issubcategoryenabled ())
		is_promptsdegraded = TRUE;

	_r_queuedlock_releaseexclusive (&lock_eventlog);

	return STATUS_SUCCESS;
}

VOID _app_eventlog_stop (VOID)
{
	EVT_HANDLE current_handle;

	_r_queuedlock_acquireexclusive (&lock_eventlog);

	current_handle = subscription_handle;
	subscription_handle = NULL;

	is_subscribed = FALSE;
	is_prompt_started = FALSE;
	is_promptsdegraded = FALSE; // intentional-off is a chosen state, not a degraded one

	_r_queuedlock_releaseexclusive (&lock_eventlog);

	if (current_handle)
		_EvtClose (current_handle); // cancels the push subscription (RSK-01: render context stays alive for in-flight callbacks)
}

BOOLEAN _app_eventlog_ishealthy (VOID)
{
	// subscribed feed + the audit subcategory actually producing 5157s
	return (is_subscribed != FALSE) && _app_audit_issubcategoryenabled ();
}

BOOLEAN _app_eventlog_ispromptdegraded (VOID)
{
	if (!is_prompt_started)
		return FALSE; // composite prompt pipeline is off this session - not degraded, just disabled (DEC-03)

	if (is_promptsdegraded)
		return TRUE;

	if (!is_subscribed)
		return TRUE; // started but the subscription is gone (RSK-08)

	return FALSE;
}
