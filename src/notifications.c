// simplewall
// Copyright (c) 2016-2026 Henry++

#include "global.h"

#include "composite_publisher.h" // composite Phase 1 (T003 tier3/T004)
#include "composite_state.h" // composite Phase 1 (T003 gate/T005 durations/T006 single-flight)

#include "composite.h"

// composite T003 (FR-02): user-space connection matcher — mirrors the
// conditions _wfp_createrulefilter would deploy for a rule part, so a
// "covered" verdict means the connection's fate is already governed by
// explicit policy (permit OR block) and prompting would be noise.
static BOOLEAN _app_notify_matchipv6prefix (
	_In_ const FWP_V6_ADDR_AND_MASK *mask,
	_In_ const IN6_ADDR *addr
)
{
	UINT8 full_bytes, rem_bits, rem_mask;

	if (mask->prefixLength > 128)
		return FALSE;

	full_bytes = (UINT8)(mask->prefixLength / 8);
	rem_bits = (UINT8)(mask->prefixLength % 8);

	if (full_bytes && memcmp (addr->u.Byte, mask->addr, full_bytes) != 0)
		return FALSE;

	if (rem_bits)
	{
		rem_mask = (UINT8)(0xFF << (8 - rem_bits));

		if ((addr->u.Byte[full_bytes] & rem_mask) != (mask->addr[full_bytes] & rem_mask))
			return FALSE;
	}

	return TRUE;
}

// match one rule part ("1.2.3.4", "1.2.3.0/24", "1.2.3.4:80", "80",
// "1000-2000") against a log item address+port on the WFP-observed side
static BOOLEAN _app_notify_matchaddresspart (
	_In_ PCR_STRINGREF part,
	_In_ ADDRESS_FAMILY af,
	_In_ const IN_ADDR *addr4,
	_In_ const IN6_ADDR *addr6,
	_In_ UINT16 port
)
{
	ITEM_ADDRESS address;
	ULONG log_addr4, range_low, range_high;
	INT cmp;

	if (!_app_parserulestring (part, &address))
		return FALSE; // unparsable parts never deployed a WFP condition either

	if (address.type == DATA_TYPE_PORT)
	{
		if (address.is_range)
			return (port >= address.range.valueLow.uint16 && port <= address.range.valueHigh.uint16);

		return (address.port == port);
	}
	else if (address.type == DATA_TYPE_IP)
	{
		// a part may carry a port too ("1.2.3.4:80")
		if (address.port && address.port != port)
			return FALSE;

		if (address.is_range)
		{
			if (address.format == NET_ADDRESS_IPV4)
			{
				if (af != AF_INET || !addr4)
					return FALSE;

				// rule ranges are host byte order; the log address is
				// stored network byte order (log.c byteswaps on ingest)
				log_addr4 = _r_byteswap_ulong (addr4->S_un.S_addr);

				range_low = address.range.valueLow.uint32;
				range_high = address.range.valueHigh.uint32;

				if (range_low > range_high)
				{
					range_low = address.range.valueHigh.uint32;
					range_high = address.range.valueLow.uint32;
				}

				return (log_addr4 >= range_low && log_addr4 <= range_high);
			}
			else if (address.format == NET_ADDRESS_IPV6)
			{
				if (af != AF_INET6 || !addr6)
					return FALSE;

				cmp = memcmp (addr6->u.Byte, address.range.valueLow.byteArray16, FWP_V6_ADDR_SIZE);

				if (cmp < 0)
					return FALSE;

				cmp = memcmp (addr6->u.Byte, address.range.valueHigh.byteArray16, FWP_V6_ADDR_SIZE);

				return (cmp <= 0);
			}

			return FALSE;
		}

		if (address.format == NET_ADDRESS_IPV4)
		{
			if (af != AF_INET || !addr4)
				return FALSE;

			// addr4.addr/addr4.mask are host byte order (same convention
			// the WFP condition uses); a zero mask matches everything,
			// exactly like the deployed condition would
			log_addr4 = _r_byteswap_ulong (addr4->S_un.S_addr);

			return ((log_addr4 & address.addr4.mask) == (address.addr4.addr & address.addr4.mask));
		}
		else if (address.format == NET_ADDRESS_IPV6)
		{
			if (af != AF_INET6 || !addr6)
				return FALSE;

			return _app_notify_matchipv6prefix (&address.addr6, addr6);
		}
	}

	return FALSE;
}

static BOOLEAN _app_notify_matchrulestring (
	_In_opt_ PCR_STRINGREF rule_string,
	_In_ ADDRESS_FAMILY af,
	_In_ const IN_ADDR *addr4,
	_In_ const IN6_ADDR *addr6,
	_In_ UINT16 port
)
{
	R_STRINGREF part, remaining;

	// note: _r_obj_isstringempty2 dereferences its argument — check for
	// NULL first (an absent rule side deploys no condition, matches all)
	if (!rule_string || _r_obj_isstringempty2 (rule_string))
		return TRUE; // empty rule string deploys no condition (matches all)

	remaining = *rule_string;

	while (remaining.length != 0)
	{
		_r_str_splitatchar (&remaining, DIVIDER_RULE[0], &part, &remaining);

		if (part.length != 0)
		{
			if (_app_notify_matchaddresspart (&part, af, addr4, addr6, port))
				return TRUE;
		}

		if (remaining.length == 0)
			break;
	}

	return FALSE;
}

// T003 tier1+2: TRUE when an enabled rule (user/system/blocklist/config —
// pack rules arrive through the same rules_list categories) already
// governs this exact connection
static BOOLEAN _app_notify_havematchingrule (
	_In_ PITEM_LOG ptr_log
)
{
	PITEM_RULE ptr_rule;
	BOOLEAN is_matched = FALSE;

	_r_queuedlock_acquireshared (&lock_rules);

	for (ULONG_PTR i = 0; i < _r_obj_getlistsize (rules_list); i++)
	{
		ptr_rule = (PITEM_RULE)_r_obj_getlistitem (rules_list, i);

		if (!ptr_rule || !ptr_rule->is_enabled)
			continue;

		// driver/service rules only ever apply to the system hashes
		if ((ptr_rule->is_fordriver || ptr_rule->is_forservice) && !_app_issystemhash (ptr_log->app_hash))
			continue;

		// app scoping: empty apps = global rule, otherwise the log's app
		// must be a member (same check _wfp_createrulefilters applies)
		if (!_r_obj_isempty (ptr_rule->apps) && !_r_obj_findhashtable (ptr_rule->apps, ptr_log->app_hash))
			continue;

		if (ptr_rule->direction != FWP_DIRECTION_MAX && ptr_rule->direction != ptr_log->direction)
			continue;

		if (ptr_rule->protocol && ptr_rule->protocol != ptr_log->protocol)
			continue;

		if (ptr_rule->af != AF_UNSPEC && ptr_rule->af != ptr_log->af)
			continue;

		if (!_app_notify_matchrulestring (
				_r_obj_isstringempty (ptr_rule->rule_remote) ? NULL : &ptr_rule->rule_remote->sr,
				ptr_log->af,
				&ptr_log->remote_addr,
				&ptr_log->remote_addr6,
				ptr_log->remote_port
			))
			continue;

		if (!_app_notify_matchrulestring (
				_r_obj_isstringempty (ptr_rule->rule_local) ? NULL : &ptr_rule->rule_local->sr,
				ptr_log->af,
				&ptr_log->local_addr,
				&ptr_log->local_addr6,
				ptr_log->local_port
			))
			continue;

		is_matched = TRUE; // permit or block — the connection is governed
		break;
	}

	_r_queuedlock_releaseshared (&lock_rules);

	return is_matched;
}

// composite T003 (FR-02): tier resolution — TRUE when the connection is
// already covered and must not prompt
static BOOLEAN _app_notify_istierscovered (
	_In_ PITEM_LOG ptr_log,
	_In_ PITEM_APP ptr_app
)
{
	PR_STRING path;

	// tier1: the app itself is enabled (permanent or temporary permit)
	if (ptr_app->is_enabled)
		return TRUE;

	// tier1+2: an enabled rule (existing, wildcard or pack category)
	// already covers the connection
	if (_app_notify_havematchingrule (ptr_log))
		return TRUE;

	// tier3: a trusted publisher anchor covers the binary (fast path:
	// already-materialized; full check verifies the signer per
	// path+mtime and lazily materializes a new path on anchor match)
	path = ptr_app->real_path ? ptr_app->real_path : ptr_app->original_path;

	if (!_r_obj_isstringempty (path) && path->buffer)
	{
		if (_app_publisher_ismaterialized (path->buffer))
			return TRUE;

		if (_app_publisher_istiercovered (ptr_app))
			return TRUE;
	}

	return FALSE;
}

_Ret_maybenull_
HWND _app_notify_getwindow (
	_In_opt_ PITEM_LOG ptr_log
)
{
	HWND hwnd = (HWND)_InterlockedCompareExchangePointer ((volatile PVOID_PTR)&config.hnotification, NULL, NULL);

	if (hwnd)
	{
		if (ptr_log)
			_app_notify_show (hwnd, ptr_log);

		return hwnd;
	}

	if (!ptr_log)
		return NULL;

	_r_wnd_createwindow (_r_sys_getimagebase (), MAKEINTRESOURCE (IDD_NOTIFICATION), NULL, &NotificationProc, ptr_log);

	_r_sys_waitforsingleobject (config.hnotify_evt, 2000);

	return (HWND)_InterlockedCompareExchangePointer ((volatile PVOID_PTR)&config.hnotification, NULL, NULL);
}

_Ret_maybenull_
PNOTIFY_CONTEXT _app_notify_getcontext (
	_In_ HWND hwnd
)
{
	return (PNOTIFY_CONTEXT)_r_wnd_getcontext (hwnd, SHORT_MAX);
}

VOID _app_notify_setcontext (
	_In_ HWND hwnd,
	_Inout_opt_ PNOTIFY_CONTEXT context
)
{
	if (context)
	{
		context->hwnd = hwnd;

		_r_wnd_setcontext (hwnd, SHORT_MAX, context);
	}
	else
	{
		_r_wnd_removecontext (hwnd, SHORT_MAX);
	}
}

BOOLEAN _app_notify_command (
	_In_ HWND hwnd,
	_In_ INT button_id,
	_In_opt_ LONG64 seconds
)
{
	PITEM_APP ptr_app;
	PITEM_LOG ptr_log;
	PR_LIST rules;
	HWND hmain;
	ULONG app_hash;
	BOOLEAN is_session;

	app_hash = _app_notify_getapp_id (hwnd);
	ptr_app = _app_getappitem (app_hash);

	if (!ptr_app)
		return FALSE;

	hmain = _r_app_gethwnd ();

	// composite T005: fetch the prompt's connection context BEFORE the
	// notification object is freed — a "once" decision deploys an
	// exact-tuple filter from it
	ptr_log = _app_notify_getobject (app_hash);

	_app_notify_freeobject (hwnd, ptr_app);

	rules = _r_obj_createlist (0x02, NULL);

	// composite T005 (FR-04/DATA-01): once/until-restart decisions live in
	// session state only (composite_state.c) — they never set is_enabled,
	// never enter rules_list and never reach profile.xml; WFP is touched
	// only through composite-owned filters that die with the session
	is_session = (seconds == STATE_SECONDS_ONCE || seconds == STATE_SECONDS_UNTILRESTART);

	if (is_session && (button_id == IDC_ALLOW_BTN || button_id == IDC_BLOCK_BTN))
	{
		_app_state_decide (
			ptr_app,
			(BOOLEAN)(button_id == IDC_BLOCK_BTN),
			(BOOLEAN)(seconds == STATE_SECONDS_ONCE),
			ptr_log,
			hmain
		);
	}
	else if (button_id == IDC_ALLOW_BTN || button_id == IDC_BLOCK_BTN)
	{
		ptr_app->is_enabled = (button_id == IDC_ALLOW_BTN);
		ptr_app->is_silent = (button_id == IDC_BLOCK_BTN);

		// composite T005: an "always" decision supersedes any session
		// decision for this app — a leftover session permit must not
		// silently override a permanent block (and vice versa); it also
		// releases the app's held-pending connections (T006 batch review)
		_app_state_revokeapp (app_hash);
		_app_state_releasepending (app_hash);

		if (ptr_app->is_enabled && seconds > 0)
		{
			_app_timer_set (hmain, ptr_app, seconds);
		}
		else
		{
			if (hmain)
				_app_listview_updateitemby_param (hmain, app_hash, TRUE);
		}

		_r_obj_addlistitem (rules, ptr_app, NULL);
	}
	else if (button_id == IDC_NEXT_BTN)
	{
		NOTHING;
	}
	else if (button_id == IDM_DISABLENOTIFICATIONS)
	{
		ptr_app->is_silent = TRUE;
	}

	ptr_app->last_notify = _r_unixtime_now (); // store last display time

	if (!_r_obj_isempty2 (rules) && _wfp_isfiltersinstalled ())
		_wfp_createappfilters (_wfp_getenginehandle (), rules, DBG_ARG, FALSE);

	if (hmain)
		_app_listview_updateby_id (hmain, ptr_app->type, PR_UPDATE_TYPE);

	_r_obj_dereference (ptr_app);
	_r_obj_dereference (rules);

	// composite T005: session decisions never touch profile.xml (DATA-01)
	if (!is_session)
		_app_profile_save (hwnd);

	if (ptr_log)
		_r_obj_dereference (ptr_log);

	return TRUE;
}

BOOLEAN _app_notify_addobject (
	_In_ HWND hwnd,
	_In_ PITEM_LOG ptr_log,
	_Inout_ PITEM_APP ptr_app
)
{
	LONG64 current_time, notification_timeout;
	HWND hmain;

	notification_timeout = _r_config_getlong64 (L"NotificationsTimeout", NOTIFY_TIMEOUT_DEFAULT, NULL);
	current_time = _r_unixtime_now ();

	// check for last display time
	if (notification_timeout > 0 && ((current_time - ptr_app->last_notify) <= notification_timeout))
		return FALSE;

	// composite T003 (FR-02): auto-tiers — before ANY prompt, resolve
	// whether current policy already covers this connection (an enabled
	// app, an enabled/wildcard/pack rule, or an already-materialized
	// trusted publisher); only genuinely novel connections prompt
	if (_r_config_getboolean (COMPOSITE_CONFIG_TIERS, TRUE, NULL))
	{
		if (_app_notify_istierscovered (ptr_log, ptr_app))
			return FALSE;
	}

	// composite T006 (FR-05): single-flight — at most ONE prompt visible;
	// concurrent novel connections take the hard default (the default-deny
	// filters at FWW_LOWEST already block; deliberately NOTHING is done to
	// WFP here) and are counted for batch review. The file/UI log already
	// fired for this event (log.c gate), which is the batch-review record.
	if (_r_config_getboolean (COMPOSITE_CONFIG_SINGLEFLIGHT, TRUE, NULL))
	{
		if ((HWND)_InterlockedCompareExchangePointer ((volatile PVOID_PTR)&config.hnotification, NULL, NULL))
		{
			_app_state_holdpending (ptr_log->app_hash);

			// best-effort throttled tray tooltip refresh with the
			// held-pending count (the tooltip builder is shared with the
			// status bar; _wfp_getinstalltype is an RPC, so no more than
			// once per second from this event-driven path)
			{
				static volatile LONG hold_refresh_tick;
				ULONG tick = GetTickCount ();
				ULONG last_tick = (ULONG)_InterlockedCompareExchange (&hold_refresh_tick, 0, 0);

				if (last_tick == 0 || (tick - last_tick) >= 1000)
				{
					_InterlockedExchange (&hold_refresh_tick, (LONG)tick);

					hmain = _r_app_gethwnd ();

					if (hmain)
						_app_settrayicon (hmain, _wfp_getinstalltype ());
				}
			}

			return FALSE;
		}
	}

	ptr_app->last_notify = current_time;

	_r_obj_swapreference ((PVOID_PTR)&ptr_app->notification, ptr_log);

	if (_r_wnd_sendmessage (hwnd, 0, WM_NOTIFICATION, 0, (LPARAM)ptr_app->notification))
	{
		if (_r_config_getboolean (L"IsNotificationsSound", TRUE, NULL) && (!_r_config_getboolean (L"IsNotificationsFullscreenSilentMode", TRUE, NULL) || !_r_wnd_isfullscreenmode ()))
			_app_notify_playsound ();

		return TRUE;
	}

	return FALSE;
}

VOID _app_notify_freeobject (
	_In_opt_ HWND hwnd,
	_Inout_ PITEM_APP ptr_app
)
{
	if (!hwnd)
		hwnd = _app_notify_getwindow (NULL);

	if (ptr_app->notification)
		_r_obj_clearreference ((PVOID_PTR)&ptr_app->notification);

	if (hwnd)
	{
		if (_app_notify_getnextapp_id (hwnd) != 0)
		{
			_app_notify_refresh (hwnd);
		}
		else
		{
			DestroyWindow (hwnd);
		}
	}
}

_Ret_maybenull_
PITEM_LOG _app_notify_getobject (
	_In_ ULONG app_hash
)
{
	PITEM_APP ptr_app;
	PITEM_LOG ptr_log;

	ptr_app = _app_getappitem (app_hash);

	if (!ptr_app)
		return NULL;

	ptr_log = (PITEM_LOG)_r_obj_referencesafe (ptr_app->notification);

	_r_obj_dereference (ptr_app);

	return ptr_log;
}

_Ret_maybenull_
HICON _app_notify_getapp_icon (
	_In_ HWND hwnd
)
{
	PNOTIFY_CONTEXT context = _app_notify_getcontext (hwnd);

	return context ? context->hicon : NULL;
}

_Success_ (return != 0)
ULONG _app_notify_getapp_id (
	_In_ HWND hwnd
)
{
	PNOTIFY_CONTEXT context = _app_notify_getcontext (hwnd);

	return context ? context->app_hash : 0;
}

_Success_ (return != 0)
ULONG _app_notify_getnextapp_id (
	_In_ HWND hwnd
)
{
	PNOTIFY_CONTEXT context;
	PITEM_APP ptr_app = NULL;
	ULONG_PTR enum_key = 0;
	ULONG app_hash = 0;

	context = _app_notify_getcontext (hwnd);

	if (context)
		app_hash = context->app_hash;

	_r_queuedlock_acquireshared (&lock_apps);

	while (_r_obj_enumhashtablepointer (apps_table, (PVOID_PTR)&ptr_app, NULL, &enum_key))
	{
		if (!ptr_app->notification)
			continue;

		// exclude current app from enumeration
		if (ptr_app->app_hash == app_hash)
			continue;

		app_hash = ptr_app->app_hash;

		break;
	}

	_r_queuedlock_releaseshared (&lock_apps);

	if (context)
		context->app_hash = app_hash;

	return app_hash;
}

VOID _app_notify_setapp_icon (
	_In_ HWND hwnd,
	_In_opt_ HICON hicon
)
{
	PNOTIFY_CONTEXT context;
	HICON hicon_prev;

	context = _app_notify_getcontext (hwnd);

	if (!context)
		return;

	if (!hicon)
		hicon = _app_icons_getdefaultapp_hicon ();

	hicon_prev = context->hicon;
	context->hicon = hicon;

	RedrawWindow (hwnd, NULL, NULL, RDW_ALLCHILDREN | RDW_ERASE | RDW_INVALIDATE);

	if (hicon_prev)
		DestroyIcon (hicon_prev);
}

VOID _app_notify_setapp_id (
	_In_ HWND hwnd,
	_In_opt_ ULONG app_hash
)
{
	PNOTIFY_CONTEXT context = _app_notify_getcontext (hwnd);

	if (context)
		context->app_hash = app_hash;
}

VOID _app_notify_show (
	_In_ HWND hwnd,
	_In_ PITEM_LOG ptr_log
)
{
	PR_STRING empty, loading, localized_string = NULL, string = NULL;
	WCHAR window_title[0x80];
	PITEM_APP ptr_app;
	HDWP hdefer;
	BOOLEAN is_fullscreenmode;

	ptr_app = _app_getappitem (ptr_log->app_hash);

	if (!ptr_app)
	{
		DestroyWindow (hwnd);
		return;
	}

	// set notification information
	_app_notify_setapp_id (hwnd, ptr_log->app_hash);
	_app_notify_setapp_icon (hwnd, NULL);

	// set window title
	_r_str_printf (window_title, RTL_NUMBER_OF (window_title), L"%s - %s", _r_locale_getstring (IDS_NOTIFY_TITLE), _r_app_getname ());

	_r_ctrl_setstring (hwnd, 0, window_title);

	hdefer = BeginDeferWindowPos (2);

	empty = _r_locale_getstring_ex (IDS_STATUS_EMPTY);

	if (_r_obj_isstringempty (empty))
		_r_obj_movereference ((PVOID_PTR)&empty, _r_obj_createstring (L"Empty..."));

	loading = _r_locale_getstring_ex (IDS_LOADING);

	if (_r_obj_isstringempty (loading))
		_r_obj_movereference ((PVOID_PTR)&loading, _r_obj_createstring (L"Loading..."));

	// print name
	_r_obj_movereference ((PVOID_PTR)&localized_string, _r_obj_concatstrings (2, _r_locale_getstring (IDS_NAME), L":"));
	_r_obj_movereference ((PVOID_PTR)&string, _app_getappdisplayname (ptr_app, TRUE));
	_r_ctrl_settablestring (hwnd, &hdefer, IDC_FILE_ID, &localized_string->sr, IDC_FILE_TEXT, string ? &string->sr : &empty->sr);

	// print signature
	_r_obj_movereference ((PVOID_PTR)&localized_string, _r_obj_concatstrings (2, _r_locale_getstring (IDS_SIGNATURE), L":"));
	_r_ctrl_settablestring (hwnd, &hdefer, IDC_SIGNATURE_ID, &localized_string->sr, IDC_SIGNATURE_TEXT, &loading->sr);

	// print address
	_r_obj_movereference ((PVOID_PTR)&localized_string, _r_obj_concatstrings (2, _r_locale_getstring (IDS_ADDRESS), L":"));
	_r_ctrl_settablestring (hwnd, &hdefer, IDC_ADDRESS_ID, &localized_string->sr, IDC_ADDRESS_TEXT, &loading->sr);

	// print host
	_r_obj_movereference ((PVOID_PTR)&localized_string, _r_obj_concatstrings (2, _r_locale_getstring (IDS_HOST), L":"));
	_r_ctrl_settablestring (hwnd, &hdefer, IDC_HOST_ID, &localized_string->sr, IDC_HOST_TEXT, &loading->sr);

	// print port
	_r_obj_movereference ((PVOID_PTR)&localized_string, _r_obj_concatstrings (2, _r_locale_getstring (IDS_PORT), L":"));
	_r_obj_movereference ((PVOID_PTR)&string, _app_formatport (ptr_log->remote_port, ptr_log->protocol));
	_r_ctrl_settablestring (hwnd, &hdefer, IDC_PORT_ID, &localized_string->sr, IDC_PORT_TEXT, string ? &string->sr : &empty->sr);

	// print direction
	_r_obj_movereference ((PVOID_PTR)&localized_string, _r_obj_concatstrings (2, _r_locale_getstring (IDS_DIRECTION), L":"));
	_r_obj_movereference ((PVOID_PTR)&string, _app_db_getdirectionname (ptr_log->direction, ptr_log->is_loopback, TRUE));
	_r_ctrl_settablestring (hwnd, &hdefer, IDC_DIRECTION_ID, &localized_string->sr, IDC_DIRECTION_TEXT, string ? &string->sr : &empty->sr);

	// print filter name
	_r_obj_movereference ((PVOID_PTR)&localized_string, _r_obj_concatstrings (2, _r_locale_getstring (IDS_FILTER), L":"));
	_r_ctrl_settablestring (hwnd, &hdefer, IDC_FILTER_ID, &localized_string->sr, IDC_FILTER_TEXT, ptr_log->filter_name ? &ptr_log->filter_name->sr : &empty->sr);

	// print date
	_r_obj_movereference ((PVOID_PTR)&localized_string, _r_obj_concatstrings (2, _r_locale_getstring (IDS_DATE), L":"));
	_r_obj_movereference ((PVOID_PTR)&string, _r_format_unixtime (ptr_log->timestamp, FDTF_SHORTDATE | FDTF_LONGTIME));
	_r_ctrl_settablestring (hwnd, &hdefer, IDC_DATE_ID, &localized_string->sr, IDC_DATE_TEXT, string ? &string->sr : &empty->sr);

	if (hdefer)
		EndDeferWindowPos (hdefer);

	//_r_ctrl_setstring (hwnd, IDC_RULES_BTN, _r_locale_getstring (IDS_TRAY_RULES));
	_r_ctrl_setstring (hwnd, IDC_ALLOW_BTN, _r_locale_getstring (IDS_ACTION_ALLOW));
	_r_ctrl_setstring (hwnd, IDC_BLOCK_BTN, _r_locale_getstring (IDS_ACTION_BLOCK));

	// prevent fullscreen apps lose focus
	is_fullscreenmode = _r_wnd_isfullscreenmode ();

	if (!is_fullscreenmode)
		_r_wnd_top (hwnd, TRUE);

	// set safety timeout
	_app_notify_settimeout (hwnd);

	// set correct position
	_app_notify_setposition (hwnd, FALSE);

	ShowWindow (hwnd, SW_SHOWNA);

	InvalidateRect (hwnd, NULL, TRUE);

	// query busy information
	_app_notify_queueinfo (hwnd, ptr_log);

	if (string)
		_r_obj_dereference (string);

	_r_obj_dereference (ptr_app);
	_r_obj_dereference (loading);
	_r_obj_dereference (empty);
}

// play notification sound even when system have "nosound" mode
VOID _app_notify_playsound ()
{
	static volatile PR_STRING cached_path = NULL;

	PR_STRING current_path, path;
	HANDLE hkey;
	ULONG flags = SND_ASYNC | SND_NODEFAULT | SND_NOWAIT | SND_SENTRY;
	NTSTATUS status;

	current_path = (PR_STRING)_InterlockedCompareExchangePointer ((volatile PVOID_PTR)&cached_path, NULL, NULL);

	if (_r_obj_isstringempty (current_path) || !_r_fs_isexists (&current_path->sr))
	{
		status = _r_reg_openkey (&hkey, HKEY_CURRENT_USER, L"AppEvents\\Schemes\\Apps\\.Default\\" NOTIFY_SOUND_NAME L"\\.Default", 0, KEY_READ);

		if (NT_SUCCESS (status))
		{
			status = _r_reg_querystring (hkey, NULL, &path, NULL);

			if (NT_SUCCESS (status))
			{
				current_path = (PR_STRING)_InterlockedCompareExchangePointer ((volatile PVOID_PTR)&cached_path, path, current_path);

				if (current_path)
					_r_obj_dereference (path);
			}

			NtClose (hkey);
		}
	}

	if (_r_obj_isstringempty (current_path) || !_r_fs_isexists (&current_path->sr) || !PlaySoundW (current_path->buffer, NULL, flags | SND_FILENAME))
		PlaySoundW (NOTIFY_SOUND_NAME, NULL, flags);
}

VOID _app_notify_queueinfo (
	_In_ HWND hwnd,
	_In_ PITEM_LOG ptr_log
)
{
	PITEM_CONTEXT context;

	context = (PITEM_CONTEXT)_r_freelist_allocateitem (&context_free_list);

	context->hwnd = hwnd;
	context->base_address = _r_obj_reference (ptr_log);

	_r_workqueue_queueitem (&resolve_notify_queue, &_app_queue_notifyinformation, context);
}

// composite T005 (FR-04): once / until-restart session durations for
// prompt decisions; opened under the popup's safety timer (BCN_DROPDOWN
// gates on _r_ctrl_isenabled — same contract as the timers menu); the
// active session decision is check-marked
static VOID _app_notify_generatedurationsmenu (
	_In_ HMENU hsubmenu,
	_In_ ULONG app_hash,
	_In_ BOOLEAN is_block
)
{
	PR_STRING string;
	UINT once_id, until_id, active_id;
	BOOLEAN is_active_block, is_active_once;

	once_id = is_block ? IDX_BLOCK_ONCE : IDX_ALLOW_ONCE;
	until_id = is_block ? IDX_BLOCK_UNTILRESTART : IDX_ALLOW_UNTILRESTART;

	string = _r_locale_getstring_ex (IDS_DECISION_ONCE);

	if (!string)
		string = _r_obj_createstring (L"Once");

	_r_menu_additem (hsubmenu, once_id, string->buffer);

	_r_obj_dereference (string);

	string = _r_locale_getstring_ex (IDS_DECISION_UNTIL_RESTART);

	if (!string)
		string = _r_obj_createstring (L"Until restart");

	_r_menu_additem (hsubmenu, until_id, string->buffer);

	_r_obj_dereference (string);

	if (_app_state_getdecision (app_hash, &is_active_block, &is_active_once) && is_active_block == is_block)
	{
		active_id = is_active_once ? once_id : until_id;

		_r_menu_checkitem (hsubmenu, active_id, active_id, MF_BYCOMMAND, active_id);
	}
}

// composite T004/T005: the Allow split-dropdown — upstream temporary
// timers, the session durations, and (only when the binary is
// signature-verified and NOT self-signed, DEC-05) "Always for publisher"
static VOID _app_notify_generateallowmenu (
	_In_ HMENU hsubmenu,
	_In_ ULONG app_hash
)
{
	PR_STRING string;

	// temporary allows (existing upstream menu)
	_app_generate_timerscontrol (hsubmenu, app_hash);

	_r_menu_addseparator (hsubmenu);

	_app_notify_generatedurationsmenu (hsubmenu, app_hash, FALSE);

	// composite T004: publisher binding (FR-03/SEC-02/DEC-05)
	if (_app_publisher_isavailable (app_hash))
	{
		_r_menu_addseparator (hsubmenu);

		string = _r_locale_getstring_ex (IDS_DECISION_PUBLISHER);

		if (!string)
			string = _r_obj_createstring (L"Always for publisher");

		_r_menu_additem (hsubmenu, IDX_PUBLISHER, string->buffer);

		_r_obj_dereference (string);
	}
}

// composite T005: the Block split-dropdown — session durations only
// (upstream has no timed blocks; the main button click stays "always")
static VOID _app_notify_generateblockmenu (
	_In_ HMENU hsubmenu,
	_In_ ULONG app_hash
)
{
	_app_notify_generatedurationsmenu (hsubmenu, app_hash, TRUE);
}

// hardening round 1 (FR-05/SEC-04/DEC-05): terminating another user's
// process requires SE_DEBUG; hold it only within this call (enable-on-
// demand, drop immediately after) instead of for the process lifetime.
static VOID _app_notify_terminateprocess (
	_In_ HWND hwnd,
	_In_ ULONG process_id,
	_In_ LPCWSTR file_name
)
{
	ULONG privileges[] = {SE_DEBUG_PRIVILEGE};
	HANDLE hprocess;
	NTSTATUS status;

	_r_sys_setprocessprivilege (hwnd, NtCurrentProcess (), privileges, RTL_NUMBER_OF (privileges), TRUE);

	status = _r_sys_openprocess (&hprocess, process_id, PROCESS_TERMINATE);

	if (NT_SUCCESS (status))
	{
		status = NtTerminateProcess (hprocess, STATUS_SUCCESS);

		if (!NT_SUCCESS (status))
			_r_show_errormessage (hwnd, L"Cannot terminate process!", file_name, status, ET_NATIVE);

		NtClose (hprocess);
	}
	else
	{
		_r_show_errormessage (hwnd, L"Cannot open process for termination!", file_name, status, ET_NATIVE);
	}

	_r_sys_setprocessprivilege (hwnd, NtCurrentProcess (), privileges, RTL_NUMBER_OF (privileges), FALSE);
}

BOOLEAN _app_notify_killprocess (
	_In_ HWND hwnd
)
{
	PSYSTEM_PROCESS_INFORMATION process, spi;
	PNOTIFY_CONTEXT context;
	PITEM_APP ptr_app;
	PR_STRING file_name, path;
	NTSTATUS status;

	context = _app_notify_getcontext (hwnd);

	if (!context)
		return FALSE;

	ptr_app = _app_getappitem (context->app_hash);

	if (!ptr_app)
		return FALSE;

	status = _r_sys_enumprocesses (&spi);

	if (!NT_SUCCESS (status))
	{
		_r_show_errormessage (hwnd, L"Could not enumerate processes!", NULL, status, ET_NATIVE);

		_r_log (LOG_LEVEL_ERROR, NULL, L"_r_sys_enumprocesses", NULL, status);

		return FALSE;
	}

	file_name = _r_path_getbasenamestring (&ptr_app->real_path->sr);

	process = PR_FIRST_PROCESS (spi);

	do
	{
		if (!process->ImageName.Buffer || process->ImageName.Length == 0)
			continue;

		if (_r_str_isequal2 (&file_name->sr, process->ImageName.Buffer, TRUE))
		{
			status = _r_sys_getprocessimagepathbyid (&path, HandleToULong (process->UniqueProcessId), TRUE);

			if (NT_SUCCESS (status))
			{
				if (_r_str_isequal (&path->sr, &ptr_app->real_path->sr, TRUE))
				{
					// hardening round 1 (FR-05/SEC-04): SE_DEBUG is held only
					// within this call, not for the process lifetime
					_app_notify_terminateprocess (hwnd, HandleToULong (process->UniqueProcessId), file_name->buffer);
				}

				_r_obj_dereference (path);
			}
			else
			{
				_r_show_errormessage (hwnd, L"Cannot get process path!", file_name->buffer, status, ET_NATIVE);
			}
		}
	}
	while ((process = PR_NEXT_PROCESS (process)));

	_r_obj_dereference (file_name);

	_r_mem_free (spi);

	return NT_SUCCESS (status);
}

VOID _app_notify_refresh (
	_In_ HWND hwnd
)
{
	PITEM_LOG ptr_log;

	if (!_r_wnd_isvisible (hwnd, TRUE) || !_r_config_getboolean (L"IsNotificationsEnabled", TRUE, NULL))
	{
		DestroyWindow (hwnd);
		return;
	}

	ptr_log = _app_notify_getobject (_app_notify_getapp_id (hwnd));

	if (!ptr_log)
	{
		DestroyWindow (hwnd);
		return;
	}

	_app_notify_show (hwnd, ptr_log);

	_r_obj_dereference (ptr_log);
}

VOID _app_notify_setposition (
	_In_ HWND hwnd,
	_In_ BOOLEAN is_forced
)
{
	MONITORINFO monitor_info = {0};
	APPBARDATA taskbar_rect = {0};
	R_RECTANGLE window_rect;
	HMONITOR hmonitor;
	PRECT rect;
	LONG border_x;

	if (!_r_wnd_getposition (hwnd, &window_rect))
		return;

	if (!is_forced && _r_wnd_isvisible (hwnd, FALSE))
	{
		_r_wnd_adjustrectangletoworkingarea (&window_rect, hwnd);
		_r_wnd_setposition (hwnd, &window_rect.position, NULL);

		return;
	}

	if (_r_config_getboolean (L"IsNotificationsOnTray", FALSE, NULL))
	{
		monitor_info.cbSize = sizeof (MONITORINFO);

		hmonitor = MonitorFromWindow (hwnd, MONITOR_DEFAULTTONEAREST);

		if (GetMonitorInfoW (hmonitor, &monitor_info))
		{
			taskbar_rect.cbSize = sizeof (APPBARDATA);

			if (SHAppBarMessage (ABM_GETTASKBARPOS, &taskbar_rect))
			{
				border_x = _r_dc_getsystemmetrics (SM_CXBORDER, _r_dc_getwindowdpi (hwnd));
				rect = &monitor_info.rcWork;

				if (taskbar_rect.uEdge == ABE_LEFT)
				{
					window_rect.left = taskbar_rect.rc.right + border_x;
					window_rect.top = (rect->bottom - window_rect.height) - border_x;
				}
				else if (taskbar_rect.uEdge == ABE_TOP)
				{
					window_rect.left = (rect->right - window_rect.width) - border_x;
					window_rect.top = taskbar_rect.rc.bottom + border_x;
				}
				else if (taskbar_rect.uEdge == ABE_RIGHT)
				{
					window_rect.left = (rect->right - window_rect.width) - border_x;
					window_rect.top = (rect->bottom - window_rect.height) - border_x;
				}
				else //if (taskbar_rect.uEdge == ABE_BOTTOM)
				{
					window_rect.left = (rect->right - window_rect.width) - border_x;
					window_rect.top = (rect->bottom - window_rect.height) - border_x;
				}

				_r_wnd_adjustrectangletoworkingarea (&window_rect, NULL);
				_r_wnd_setposition (hwnd, &window_rect.position, NULL);

				return;
			}
		}
	}

	// display window on center (depends on error, config etc...)
	_r_wnd_center (hwnd, NULL);

	_r_window_restoreposition (hwnd, L"notification");
}

VOID _app_notify_settimeout (
	_In_ HWND hwnd
)
{
	_r_ctrl_enable (hwnd, IDC_KILLPROCESS_BTN, FALSE);
	_r_ctrl_enable (hwnd, IDC_RULES_BTN, FALSE);
	_r_ctrl_enable (hwnd, IDC_ALLOW_BTN, FALSE);
	_r_ctrl_enable (hwnd, IDC_BLOCK_BTN, FALSE);
	_r_ctrl_enable (hwnd, IDC_NEXT_BTN, FALSE);

	_r_sys_settimer (hwnd, GENERAL_ID, NOTIFY_TIMER_SAFETY_TIMEOUT, NULL);
}

VOID _app_notify_initialize (
	_Inout_ PNOTIFY_CONTEXT context,
	_In_ LONG dpi_value
)
{
	NONCLIENTMETRICS ncm = {0};
	HBITMAP hbmp_allow, hbmp_block, hbmp_cross, hbmp_next, hbmp_rules;
	LONG icon_large, icon_small;

	// destroy previous resources
	SAFE_DELETE_OBJECT (context->hfont_title);
	SAFE_DELETE_OBJECT (context->hfont_link);
	SAFE_DELETE_OBJECT (context->hfont_text);

	SAFE_DELETE_ICON (context->hico_allow);
	SAFE_DELETE_ICON (context->hico_block);
	SAFE_DELETE_ICON (context->hico_cross);
	SAFE_DELETE_ICON (context->hico_next);
	SAFE_DELETE_ICON (context->hico_rules);

	icon_small = _r_dc_getsystemmetrics (SM_CXSMICON, dpi_value);
	icon_large = _r_dc_getsystemmetrics (SM_CXICON, dpi_value);

	// set window icon
	_r_wnd_seticon (context->hwnd, _r_sys_loadsharedicon (NULL, MAKEINTRESOURCE (SIH_EXCLAMATION), icon_small), _r_sys_loadsharedicon (NULL, MAKEINTRESOURCE (SIH_EXCLAMATION), icon_large));

	// set window font
	ncm.cbSize = sizeof (NONCLIENTMETRICS);

	if (_r_dc_getsystemparametersinfo (SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, dpi_value))
	{
		context->hfont_title = _app_createfont (&ncm.lfCaptionFont, 12, FALSE, dpi_value);
		context->hfont_link = _app_createfont (&ncm.lfMessageFont, 9, TRUE, dpi_value);
		context->hfont_text = _app_createfont (&ncm.lfMessageFont, 9, FALSE, dpi_value);

		_r_ctrl_setfont (context->hwnd, 0, context->hfont_text);

		_r_ctrl_setfont (context->hwnd, IDC_HEADER_ID, context->hfont_title);
		_r_ctrl_setfont (context->hwnd, IDC_FILE_TEXT, context->hfont_link);

		for (INT i = IDC_SIGNATURE_TEXT; i <= IDC_DATE_TEXT; i++)
			_r_edit_setmargin (context->hwnd, i, 0, 0);

		for (INT i = IDC_SIGNATURE_TEXT; i <= IDC_NEXT_BTN; i++)
			_r_ctrl_setfont (context->hwnd, i, context->hfont_text);
	}

	// load images
	_r_res_loadimage (&hbmp_rules, _r_sys_getimagebase (), L"PNG", MAKEINTRESOURCE (IDP_SETTINGS), &GUID_ContainerFormatPng, icon_small, icon_small);
	_r_res_loadimage (&hbmp_allow, _r_sys_getimagebase (), L"PNG", MAKEINTRESOURCE (IDP_ALLOW), &GUID_ContainerFormatPng, icon_small, icon_small);
	_r_res_loadimage (&hbmp_block, _r_sys_getimagebase (), L"PNG", MAKEINTRESOURCE (IDP_BLOCK), &GUID_ContainerFormatPng, icon_small, icon_small);
	_r_res_loadimage (&hbmp_cross, _r_sys_getimagebase (), L"PNG", MAKEINTRESOURCE (IDP_CROSS), &GUID_ContainerFormatPng, icon_small, icon_small);
	_r_res_loadimage (&hbmp_next, _r_sys_getimagebase (), L"PNG", MAKEINTRESOURCE (IDP_NEXT), &GUID_ContainerFormatPng, icon_small, icon_small);

	// set button configuration
	if (hbmp_rules)
	{
		context->hico_rules = _r_dc_bitmaptoicon (hbmp_rules, icon_small, icon_small);

		DeleteObject (hbmp_rules);
	}

	if (hbmp_cross)
	{
		context->hico_cross = _r_dc_bitmaptoicon (hbmp_cross, icon_small, icon_small);

		DeleteObject (hbmp_cross);
	}

	if (hbmp_allow)
	{
		context->hico_allow = _r_dc_bitmaptoicon (hbmp_allow, icon_small, icon_small);

		DeleteObject (hbmp_allow);
	}

	if (hbmp_block)
	{
		context->hico_block = _r_dc_bitmaptoicon (hbmp_block, icon_small, icon_small);

		DeleteObject (hbmp_block);
	}

	if (hbmp_next)
	{
		context->hico_next = _r_dc_bitmaptoicon (hbmp_next, icon_small, icon_small);

		DeleteObject (hbmp_next);
	}

	_r_button_seticon (context->hwnd, IDC_RULES_BTN, context->hico_rules);
	_r_button_seticon (context->hwnd, IDC_KILLPROCESS_BTN, context->hico_cross);
	_r_button_seticon (context->hwnd, IDC_ALLOW_BTN, context->hico_allow);
	_r_button_seticon (context->hwnd, IDC_BLOCK_BTN, context->hico_block);
	_r_button_seticon (context->hwnd, IDC_NEXT_BTN, context->hico_next);

	_r_button_setmargins (context->hwnd, IDC_RULES_BTN, dpi_value);
	_r_button_setmargins (context->hwnd, IDC_KILLPROCESS_BTN, dpi_value);
	_r_button_setmargins (context->hwnd, IDC_ALLOW_BTN, dpi_value);
	_r_button_setmargins (context->hwnd, IDC_BLOCK_BTN, dpi_value);
	_r_button_setmargins (context->hwnd, IDC_NEXT_BTN, dpi_value);
}

VOID _app_notify_destroy (
	_In_ HWND hwnd
)
{
	PNOTIFY_CONTEXT context;

	_InterlockedCompareExchangePointer ((volatile PVOID_PTR)&config.hnotification, NULL, config.hnotification);

	context = _app_notify_getcontext (hwnd);

	if (!context)
		return;

	// remove context
	_app_notify_setcontext (hwnd, NULL);

	SAFE_DELETE_OBJECT (context->hfont_title);
	SAFE_DELETE_OBJECT (context->hfont_link);
	SAFE_DELETE_OBJECT (context->hfont_text);
	SAFE_DELETE_ICON (context->hico_allow);
	SAFE_DELETE_ICON (context->hico_block);
	SAFE_DELETE_ICON (context->hico_cross);
	SAFE_DELETE_ICON (context->hico_rules);
	SAFE_DELETE_ICON (context->hicon);

	_r_mem_free (context); // cleanup!
}

VOID _app_notify_drawgradient (
	_In_ HDC hdc,
	_In_ LPCRECT rect
)
{
	COLORREF gradient_arr[] = {RGB (0, 68, 112), RGB (7, 111, 95)};
	GRADIENT_RECT gradient_rect = {0};
	TRIVERTEX trivertx[2] = {0};

	static_assert (RTL_NUMBER_OF (gradient_arr) == RTL_NUMBER_OF (trivertx), "Invalid array size!");

	gradient_rect.LowerRight = 1;
	gradient_rect.UpperLeft = 0;

	for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (trivertx); i++)
	{
		trivertx[i].Red = GetRValue (gradient_arr[i]) << 8;
		trivertx[i].Green = GetGValue (gradient_arr[i]) << 8;
		trivertx[i].Blue = GetBValue (gradient_arr[i]) << 8;

		if (i == 0)
		{
			trivertx[i].x = -1;
			trivertx[i].y = -1;
		}
		else
		{
			trivertx[i].x = rect->right;
			trivertx[i].y = rect->bottom;
		}
	}

	GradientFill (hdc, trivertx, RTL_NUMBER_OF (trivertx), &gradient_rect, 1, GRADIENT_FILL_RECT_H);
}

INT_PTR CALLBACK NotificationProc (
	_In_ HWND hwnd,
	_In_ UINT msg,
	_In_ WPARAM wparam,
	_In_ LPARAM lparam
)
{
	switch (msg)
	{
		case WM_INITDIALOG:
		{
			PNOTIFY_CONTEXT context;
			PITEM_LOG ptr_log;
			HWND current_hwnd, htip;

			current_hwnd = (HWND)_InterlockedCompareExchangePointer ((volatile PVOID_PTR)&config.hnotification, hwnd, config.hnotification);

			if (current_hwnd)
				DestroyWindow (current_hwnd);

			// initialize window context
			context = (PNOTIFY_CONTEXT)_r_mem_allocate (sizeof (NOTIFY_CONTEXT));

			_app_notify_setcontext (hwnd, context);

			// set correct position
			_app_notify_setposition (hwnd, FALSE);

			_app_notify_initialize (context, _r_dc_getwindowdpi (hwnd));

			// initialize tips
			htip = _r_tooltip_create (hwnd);

			if (htip)
			{
				_r_tooltip_settext (htip, hwnd, IDC_FILE_TEXT, LPSTR_TEXTCALLBACK);
				_r_tooltip_settext (htip, hwnd, IDC_RULES_BTN, LPSTR_TEXTCALLBACK);
				_r_tooltip_settext (htip, hwnd, IDC_KILLPROCESS_BTN, LPSTR_TEXTCALLBACK);
				_r_tooltip_settext (htip, hwnd, IDC_ALLOW_BTN, LPSTR_TEXTCALLBACK);
				_r_tooltip_settext (htip, hwnd, IDC_BLOCK_BTN, LPSTR_TEXTCALLBACK);
				_r_tooltip_settext (htip, hwnd, IDC_NEXT_BTN, LPSTR_TEXTCALLBACK);
			}

			// display log information
			ptr_log = (PITEM_LOG)lparam;

			_app_notify_show (hwnd, ptr_log);

			NtSetEvent (config.hnotify_evt, NULL);

			_r_obj_dereference (ptr_log);

			_r_theme_initialize (hwnd);

			break;
		}

		case WM_CLOSE:
		{
			DestroyWindow (hwnd);
			break;
		}

		case WM_DESTROY:
		{
			_r_window_saveposition (hwnd, L"notification");
			break;
		}

		case WM_NCDESTROY:
		{
			_app_notify_destroy (hwnd);
			break;
		}

		case WM_TIMER:
		{
			KillTimer (hwnd, wparam);

			if (wparam != GENERAL_ID)
				break;

			_r_ctrl_enable (hwnd, IDC_RULES_BTN, TRUE);
			_r_ctrl_enable (hwnd, IDC_KILLPROCESS_BTN, TRUE);
			_r_ctrl_enable (hwnd, IDC_ALLOW_BTN, TRUE);
			_r_ctrl_enable (hwnd, IDC_BLOCK_BTN, TRUE);
			_r_ctrl_enable (hwnd, IDC_NEXT_BTN, TRUE);

			break;
		}

		case WM_DPICHANGED:
		{
			PNOTIFY_CONTEXT context = _app_notify_getcontext (hwnd);

			_r_wnd_message_dpichanged (hwnd, wparam, lparam);

			if (context)
				_app_notify_initialize (context, LOWORD (wparam));

			_app_notify_refresh (hwnd);

			break;
		}

		case WM_SETTINGCHANGE:
		{
			_r_wnd_message_settingchange (hwnd, wparam, lparam);
			break;
		}

		case WM_PAINT:
		{
			PAINTSTRUCT ps;
			HDC hdc;

			hdc = BeginPaint (hwnd, &ps);

			if (!hdc)
				break;

			_r_dc_drawwindow (hdc, hwnd, TRUE);

			EndPaint (hwnd, &ps);

			break;
		}

		case WM_CTLCOLORDLG:
		case WM_CTLCOLORSTATIC:
		{
			HDC hdc = (HDC)wparam;
			INT text_clr = (msg == WM_CTLCOLORSTATIC && GetDlgCtrlID ((HWND)lparam) == IDC_FILE_TEXT) ? COLOR_HIGHLIGHT : COLOR_WINDOWTEXT;

			SetBkMode (hdc, TRANSPARENT); // HACK!!!

			SetTextColor (hdc, GetSysColor (text_clr));
			SetDCBrushColor (hdc, GetSysColor (COLOR_WINDOW));

			return (INT_PTR)GetStockObject (DC_BRUSH);
		}

		case WM_DRAWITEM:
		{
			LPDRAWITEMSTRUCT draw_info = (LPDRAWITEMSTRUCT)lparam;
			PR_STRING string;
			HICON hicon;
			RECT rect;
			LONG dpi_value, icon_size_x, wnd_spacing;

			if (draw_info->CtlID != IDC_HEADER_ID)
				break;

			dpi_value = _r_dc_getwindowdpi (hwnd);

			icon_size_x = _r_dc_getsystemmetrics (SM_CXICON, dpi_value);
			wnd_spacing = _r_dc_getdpi (12, dpi_value);

			SetBkMode (draw_info->hDC, TRANSPARENT); // HACK!!!

			// draw title gradient
			_app_notify_drawgradient (draw_info->hDC, &draw_info->rcItem);

			// draw title text
			string = _r_locale_getstring_ex (IDS_NOTIFY_HEADER);

			if (string)
			{
				SetTextColor (draw_info->hDC, RGB (255, 255, 255));
				SetRect (&rect, wnd_spacing, 0, _r_calc_rectwidth (&draw_info->rcItem) - (wnd_spacing * 3) - icon_size_x, _r_calc_rectheight (&draw_info->rcItem));

				_r_dc_drawtext (NULL, draw_info->hDC, &string->sr, &rect, 0, 0, DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOCLIP | DT_NOPREFIX, 0);

				_r_obj_dereference (string);
			}

			// draw title icon
			hicon = _app_notify_getapp_icon (hwnd);

			if (hicon)
			{
				SetRect (&rect, _r_calc_rectwidth (&draw_info->rcItem) - icon_size_x - wnd_spacing, (_r_calc_rectheight (&draw_info->rcItem) / 2) - (icon_size_x / 2), icon_size_x, icon_size_x);

				DrawIconEx (draw_info->hDC, rect.left, rect.top, hicon, rect.right, rect.bottom, 0, NULL, DI_IMAGE | DI_MASK);
			}

			SetWindowLongPtrW (hwnd, DWLP_MSGRESULT, TRUE);

			return TRUE;
		}

		case WM_SETCURSOR:
		{
			if (GetDlgCtrlID ((HWND)wparam) == IDC_FILE_TEXT)
			{
				SetCursor (LoadCursorW (NULL, IDC_HAND));

				SetWindowLongPtrW (hwnd, DWLP_MSGRESULT, TRUE);

				return TRUE;
			}

			break;
		}

		case WM_LBUTTONDOWN:
		{
			_r_wnd_sendmessage (hwnd, 0, WM_SYSCOMMAND, SC_MOVE | HTCAPTION, 0);
			break;
		}

		case WM_ENTERSIZEMOVE:
		case WM_EXITSIZEMOVE:
		case WM_CAPTURECHANGED:
		{
			LONG_PTR ex_style = _r_wnd_getstyle (hwnd, GWL_EXSTYLE);

			if (!(ex_style & WS_EX_LAYERED))
				_r_wnd_setstyle (hwnd, WS_EX_LAYERED, WS_EX_LAYERED, GWL_EXSTYLE);

			SetLayeredWindowAttributes (hwnd, 0, (msg == WM_ENTERSIZEMOVE) ? 150 : 255, LWA_ALPHA);
			SetCursor (LoadCursorW (NULL, (msg == WM_ENTERSIZEMOVE) ? IDC_SIZEALL : IDC_ARROW));

			break;
		}

		case WM_NOTIFY:
		{
			LPNMHDR nmlp = (LPNMHDR)lparam;

			switch (nmlp->code)
			{
				case BCN_DROPDOWN:
				{
					PNOTIFY_CONTEXT context;
					R_RECTANGLE rectangle;
					PITEM_LOG ptr_log;
					RECT rect;
					HMENU hsubmenu;

					context = _app_notify_getcontext (hwnd);

					if (!context || !_r_ctrl_isenabled (hwnd, (INT)(INT_PTR)nmlp->idFrom))
						break;

					if (nmlp->idFrom != IDC_ALLOW_BTN && nmlp->idFrom != IDC_RULES_BTN && nmlp->idFrom != IDC_BLOCK_BTN)
						break;

					ptr_log = _app_notify_getobject (context->app_hash);

					hsubmenu = CreatePopupMenu ();

					if (!hsubmenu)
						break;

					if (nmlp->idFrom == IDC_RULES_BTN)
					{
						_app_generate_rulescontrol (hsubmenu, context->app_hash, ptr_log);
					}
					else if (nmlp->idFrom == IDC_ALLOW_BTN)
					{
						// composite T004/T005: timers + session durations +
						// "Always for publisher" (available only when the
						// binary is signature-verified and not self-signed)
						_app_notify_generateallowmenu (hsubmenu, context->app_hash);
					}
					else if (nmlp->idFrom == IDC_BLOCK_BTN)
					{
						// composite T005: session durations for block decisions
						_app_notify_generateblockmenu (hsubmenu, context->app_hash);
					}

					if (GetClientRect (nmlp->hwndFrom, &rect))
					{
						ClientToScreen (nmlp->hwndFrom, (PPOINT)&rect);

						_r_wnd_recttorectangle (&rectangle, &rect);
						_r_wnd_adjustrectangletoworkingarea (&rectangle, nmlp->hwndFrom);
						_r_wnd_rectangletorect (&rect, &rectangle);

						_r_menu_popup (hsubmenu, hwnd, (PPOINT)&rect, 0);
					}

					DestroyMenu (hsubmenu);

					break;
				}

				case TTN_GETDISPINFO:
				{
					LPNMTTDISPINFOW lpnmdi = (LPNMTTDISPINFOW)lparam;
					WCHAR buffer[0x200] = {0};
					PR_STRING string;
					HWND hmain;
					ULONG app_hash;
					INT ctrl_id, listview_id = 0;

					if ((lpnmdi->uFlags & TTF_IDISHWND) == 0)
						break;

					ctrl_id = GetDlgCtrlID ((HWND)lpnmdi->hdr.idFrom);

					if (ctrl_id == IDC_FILE_TEXT)
					{
						app_hash = _app_notify_getapp_id (hwnd);

						hmain = _r_app_gethwnd ();

						if (hmain)
						{
							if (_app_getappinfobyhash (app_hash, INFO_LISTVIEW_ID, &listview_id, sizeof (INT)))
							{
								string = _app_gettooltipbylparam (hmain, listview_id, app_hash);

								if (string)
								{
									_r_str_copy (buffer, RTL_NUMBER_OF (buffer), string->buffer);

									_r_obj_dereference (string);
								}
							}
						}
					}
					else if (ctrl_id == IDC_RULES_BTN)
					{
						_r_str_copy (buffer, RTL_NUMBER_OF (buffer), _r_locale_getstring (IDS_NOTIFY_TOOLTIP));
					}
					else if (ctrl_id == IDC_ALLOW_BTN)
					{
						_r_str_copy (buffer, RTL_NUMBER_OF (buffer), _r_locale_getstring (IDS_ACTION_ALLOW_HINT));
					}
					else if (ctrl_id == IDC_BLOCK_BTN)
					{
						_r_str_copy (buffer, RTL_NUMBER_OF (buffer), _r_locale_getstring (IDS_ACTION_BLOCK_HINT));
					}
					else if (ctrl_id == IDC_KILLPROCESS_BTN)
					{
						_r_str_copy (buffer, RTL_NUMBER_OF (buffer), _r_locale_getstring (IDS_ACTION_TERMINATE_HINT));
					}
					else if (ctrl_id == IDC_NEXT_BTN)
					{
						_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"NEXT!");
					}
					else
					{
						string = _r_ctrl_getstring (hwnd, ctrl_id);

						if (string)
						{
							_r_str_copy (buffer, RTL_NUMBER_OF (buffer), string->buffer);

							_r_obj_dereference (string);
						}
					}

					if (!_r_str_isempty2 (buffer))
						lpnmdi->lpszText = buffer;

					break;
				}
			}

			break;
		}

		case WM_COMMAND:
		{
			INT ctrl_id = LOWORD (wparam);

				if (ctrl_id >= IDX_RULES_SPECIAL && ctrl_id <= IDX_RULES_SPECIAL + (INT)(INT_PTR)_r_obj_getlistsize (rules_list) + 1)
				{
					PITEM_RULE ptr_rule;
					PITEM_APP ptr_app;
					PITEM_LOG ptr_log;
					PR_STRING rule;
					PR_LIST rules;
					HWND hmain;
					ULONG_PTR rule_idx;
					ULONG app_hash;
					BOOLEAN is_remove;

					// hardening round 1 (FR-07/SEC-05): rule-minting from the
					// notification window is gated like ALLOW/BLOCK — no
					// action before the safety timer arms the window
					if (!_r_ctrl_isenabled (hwnd, IDC_ALLOW_BTN))
						return FALSE;

					app_hash = _app_notify_getapp_id (hwnd);
				ptr_app = _app_getappitem (app_hash);

				if (!ptr_app)
					return FALSE;

				rule_idx = (ULONG_PTR)(ctrl_id - IDX_RULES_SPECIAL);
				ptr_rule = _app_getrulebyid (rule_idx);

				hmain = _r_app_gethwnd ();

				if (!ptr_rule)
				{
					ptr_log = _app_notify_getobject (app_hash);

					if (ptr_log)
					{
						rule = _app_formataddress (ptr_log->af, 0, &ptr_log->remote_addr, ptr_log->remote_port, FMTADDR_AS_RULE);

						ptr_rule = _app_addrule (NULL, NULL, NULL, FWP_DIRECTION_OUTBOUND, FWP_ACTION_PERMIT, ptr_log->protocol, ptr_log->af);

						_r_obj_movereference ((PVOID_PTR)&ptr_rule->name, _r_obj_createstring2 (&rule->sr));
						_r_obj_movereference ((PVOID_PTR)&ptr_rule->rule_remote, _r_obj_createstring2 (&rule->sr));

						_app_ruleenable (ptr_rule, TRUE, FALSE);

						_r_obj_addhashtableitem (ptr_rule->apps, app_hash, NULL);

						_r_queuedlock_acquireexclusive (&lock_rules);
						_r_obj_addlistitem (rules_list, ptr_rule, &rule_idx);
						_r_queuedlock_releaseexclusive (&lock_rules);

						if (hmain)
						{
							_app_listview_addruleitem (hmain, ptr_rule, rule_idx, TRUE);
							_app_listview_updateby_id (hmain, DATA_LISTVIEW_CURRENT, PR_UPDATE_TYPE);
						}

						_app_profile_save (hwnd);

						_r_obj_dereference (rule);
					}

					_app_notify_freeobject (hwnd, ptr_app);

					break;
				}

				_app_notify_freeobject (hwnd, ptr_app);

				if (!((ptr_rule->is_fordriver || ptr_rule->is_forservice) && _app_issystemhash (app_hash)))
				{
					is_remove = ptr_rule->is_enabled && _r_obj_findhashtable (ptr_rule->apps, app_hash);

					if (is_remove)
					{
						_r_obj_removehashtableitem (ptr_rule->apps, app_hash);

						if (_r_obj_isempty (ptr_rule->apps))
							_app_ruleenable (ptr_rule, FALSE, TRUE);
					}
					else
					{
						_r_obj_addhashtableitem (ptr_rule->apps, app_hash, NULL);

						_app_ruleenable (ptr_rule, TRUE, TRUE);
					}

					if (hmain)
					{
						_app_listview_updateitemby_param (hmain, app_hash, TRUE);
						_app_listview_updateitemby_param (hmain, rule_idx, FALSE);
					}

					if (_wfp_isfiltersinstalled ())
					{
						rules = _r_obj_createlist (0x02, NULL);

						_r_obj_addlistitem (rules, ptr_rule, NULL);

						_wfp_createrulefilters (_wfp_getenginehandle (), rules, DBG_ARG, FALSE);

						_r_obj_dereference (rules);
					}

					if (hmain)
						_app_listview_updateby_id (hmain, DATA_LISTVIEW_CURRENT, PR_UPDATE_TYPE);

					_r_obj_dereference (ptr_rule);
					_r_obj_dereference (ptr_app);

					_app_profile_save (hwnd);
				}

				return FALSE;
			}
			else if (ctrl_id >= IDX_TIMER && ctrl_id <= (IDX_TIMER + (RTL_NUMBER_OF (timer_array) - 1)))
			{
				ULONG_PTR timer_idx;

				if (!_r_ctrl_isenabled (hwnd, IDC_ALLOW_BTN))
					return FALSE;

				timer_idx = (ULONG_PTR)(ctrl_id - IDX_TIMER);

				_app_notify_command (hwnd, IDC_ALLOW_BTN, timer_array[timer_idx]);

				return FALSE;
			}
			else if (ctrl_id >= IDX_ALLOW_ONCE && ctrl_id <= IDX_BLOCK_UNTILRESTART)
			{
				// composite T005 (FR-04/DATA-01): once / until-restart
				// session decisions — gated on the owning button's safety timer
				INT duration_btn;
				LONG64 duration_seconds;

				duration_btn = (ctrl_id == IDX_ALLOW_ONCE || ctrl_id == IDX_ALLOW_UNTILRESTART) ? IDC_ALLOW_BTN : IDC_BLOCK_BTN;

				if (!_r_ctrl_isenabled (hwnd, duration_btn))
					return FALSE;

				duration_seconds = (ctrl_id == IDX_ALLOW_ONCE || ctrl_id == IDX_BLOCK_ONCE) ? STATE_SECONDS_ONCE : STATE_SECONDS_UNTILRESTART;

				_app_notify_command (hwnd, duration_btn, duration_seconds);

				return FALSE;
			}
			else if (ctrl_id == IDX_PUBLISHER)
			{
				// composite T004 (FR-03/SEC-02/DEC-05): "Always for publisher" —
				// store the signer-hash anchor + materialize per-path PERMIT
				// filters; gated on the Allow safety timer like every decision
				PITEM_APP ptr_app;
				ULONG app_hash;

				if (_r_ctrl_isenabled (hwnd, IDC_ALLOW_BTN))
				{
					app_hash = _app_notify_getapp_id (hwnd);

					ptr_app = _app_getappitem (app_hash);

					if (ptr_app)
					{
						_app_publisher_bind (hwnd, ptr_app);

						// the binding covers the app's held-pending connections
						_app_state_releasepending (app_hash);

						_app_notify_freeobject (hwnd, ptr_app);

						_r_obj_dereference (ptr_app);
					}
				}

				return FALSE;
			}

			switch (ctrl_id)
			{
				case IDCANCEL: // process Esc key
				{
					DestroyWindow (hwnd);
					break;
				}

				case IDC_FILE_TEXT:
				{
					ULONG app_hash;

					if (!_r_app_gethwnd ())
						break;

					app_hash = _app_notify_getapp_id (hwnd);

					if (app_hash)
						_app_listview_showitemby_param (_r_app_gethwnd (), app_hash, TRUE);

					break;
				}

				case IDC_RULES_BTN:
				{
					PEDITOR_CONTEXT context;
					PITEM_APP ptr_app;

					ptr_app = _app_getappitem (_app_notify_getapp_id (hwnd));

					if (!ptr_app)
						break;

					context = _app_editor_createwindow (_r_app_gethwnd (), ptr_app, 1, FALSE);

					if (context)
						_app_editor_deletewindow (context);

					_app_notify_freeobject (hwnd, ptr_app);

					_r_obj_dereference (ptr_app);

					break;
				}

				case IDC_ALLOW_BTN:
				case IDC_BLOCK_BTN:
				case IDC_NEXT_BTN:
				{
					if (_r_ctrl_isenabled (hwnd, ctrl_id))
						_app_notify_command (hwnd, ctrl_id, 0);

					break;
				}

				case IDC_KILLPROCESS_BTN:
				{
					// hardening round 1 (FR-07/SEC-05): gated like ALLOW/BLOCK —
					// no kill before the safety timer arms the window
					if (_r_ctrl_isenabled (hwnd, ctrl_id) && _app_notify_killprocess (hwnd))
						_r_ctrl_enable (hwnd, ctrl_id, FALSE);

					break;
				}

				case IDM_OPENRULESEDITOR:
				{
					PR_STRING app_name, rule_name, rule_string;
					PEDITOR_CONTEXT context;
					PITEM_RULE ptr_rule;
					PITEM_APP ptr_app;
					PITEM_LOG ptr_log;
					HWND hmain;
					ULONG_PTR rule_idx;

					ptr_log = _app_notify_getobject (_app_notify_getapp_id (hwnd));

					if (!ptr_log)
						break;

					ptr_app = _app_getappitem (ptr_log->app_hash);

					if (!ptr_app)
					{
						_r_obj_dereference (ptr_log);
						break;
					}

					app_name = _app_getappdisplayname (ptr_app, TRUE);
					rule_string = _app_formataddress (ptr_log->af, 0, &ptr_log->remote_addr, ptr_log->remote_port, FMTADDR_AS_RULE);
					rule_name = _r_format_string (L"%s - %s", _r_obj_getstring (app_name), _r_obj_getstring (rule_string));

					ptr_rule = _app_addrule (rule_name, rule_string, NULL, ptr_log->direction, FWP_ACTION_PERMIT, ptr_log->protocol, ptr_log->af);

					_r_obj_addhashtableitem (ptr_rule->apps, ptr_log->app_hash, NULL);

					_app_ruleenable (ptr_rule, TRUE, TRUE);

					context = _app_editor_createwindow (_r_app_gethwnd (), ptr_rule, 0, TRUE);

					if (context)
					{
						_r_queuedlock_acquireexclusive (&lock_rules);
						_r_obj_addlistitem (rules_list, _r_obj_reference (ptr_rule), &rule_idx);
						_r_queuedlock_releaseexclusive (&lock_rules);

						hmain = _r_app_gethwnd ();

						// set rule information
						if (hmain)
						{
							_app_listview_addruleitem (hmain, ptr_rule, rule_idx, TRUE);

							// update app information
							_app_listview_updateitemby_param (hmain, ptr_log->app_hash, TRUE);

							_app_listview_updateby_id (hmain, DATA_LISTVIEW_CURRENT, PR_UPDATE_TYPE);
						}

						_app_profile_save (hwnd);

						_app_editor_deletewindow (context);
					}

					_app_notify_freeobject (hwnd, ptr_app);

					if (rule_string)
						_r_obj_dereference (rule_string);

					if (app_name)
						_r_obj_dereference (app_name);

					_r_obj_dereference (rule_name);
					_r_obj_dereference (ptr_rule);
					_r_obj_dereference (ptr_log);
					_r_obj_dereference (ptr_app);

					break;
				}

				case IDM_COPY: // ctrl+c
				case IDM_SELECT_ALL: // ctrl+a
				{
					R_STRINGREF sr = PR_STRINGREF_INIT (WC_EDIT);
					PR_STRING class_name;
					HWND hedit;

					hedit = GetFocus ();

					if (!hedit)
						break;

					class_name = _r_wnd_getclassname (hedit);

					if (!class_name)
						break;

					if (_r_str_isequal (&class_name->sr, &sr, TRUE))
					{
						if (ctrl_id == IDM_COPY)
						{
							_r_wnd_sendmessage (hedit, 0, WM_COPY, 0, 0); // edit control hotkey for "ctrl+c" (issue #597)
						}
						else if (ctrl_id == IDM_SELECT_ALL)
						{
							_r_edit_setselection (hedit, 0, 0, -1); // edit control hotkey for "ctrl+a"
						}
					}

					_r_obj_dereference (class_name);

					break;
				}
			}

			break;
		}
	}

	return FALSE;
}
