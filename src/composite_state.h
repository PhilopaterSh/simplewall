// composite_state: prompting session state (T005/T006) + namespaced
// sidecar state IO home (DATA-01).
//
// T005 durations (FR-04/DATA-01): "once" and "until-restart" prompt
// decisions live in this module's in-memory tables and deploy as
// composite-owned WFP filters — they never set is_enabled, never insert
// into rules_list and never reach profile.xml. Sidecar persistence is
// intentionally NOT implemented here (T009); the tables are memory-only
// and die with the session by design.
//
// T006 single-flight (FR-05): held-pending counter for novel connections
// diverted while a prompt is visible (they take the hard default block —
// the default-deny filters already block; this module does nothing to
// WFP for them), surfaced on the tray tooltip/status bar.
//
// Sidecar files (T009, namespaced, never inside profile.xml — DATA-01):
// pack state, ledger baseline, audit-policy inventory; hash-checked at
// load from Phase 1 (FR-08) with ledger integrity in Phase 2 (FR-12).

#pragma once

#include <windows.h>

#include "main.h"

// config keys (namespaced, DEC-09); defaults TRUE — the feature set is
// the point of composite Phase 1
#define COMPOSITE_CONFIG_TIERS L"IsCompositeTiersEnabled" // FR-02 resolver gate (T003)
#define COMPOSITE_CONFIG_SINGLEFLIGHT L"IsCompositeSingleFlightEnabled" // FR-05 gate (T006)

// session decision lifetimes (T005); STATE_SECONDS_ALWAYS (0) is the
// upstream "permanent" behavior and never reaches this module
#define STATE_SECONDS_ONCE (-1) // session decision, exact connection, short expiry
#define STATE_SECONDS_UNTILRESTART (-2) // session decision, app-wide, until exit

#define STATE_ONCE_EXPIRY_SECONDS (2LL * 60LL) // "once" auto-expiry (shortest upstream temporary timer)

NTSTATUS _app_state_initialize (VOID);
VOID _app_state_uninitialize (VOID);

// T005: record a session-only decision for the app and deploy its
// composite-owned filters. is_block selects permit/block, is_once selects
// the exact-connection short-lived variant (requires ptr_log for the
// connection tuple; falls back to app-wide when absent).
BOOLEAN _app_state_decide (
	_In_ PITEM_APP ptr_app,
	_In_ BOOLEAN is_block,
	_In_ BOOLEAN is_once,
	_In_opt_ PITEM_LOG ptr_log,
	_In_opt_ HWND hwnd
);

// T005: TRUE when the app has a live session decision (menu checkmark);
// outputs are optional
BOOLEAN _app_state_getdecision (
	_In_ ULONG app_hash,
	_Out_opt_ PBOOLEAN is_block,
	_Out_opt_ PBOOLEAN is_once
);

// T005: drop the app's session decisions — invoked before any "always"
// decision so a permanent block is not silently overridden by a leftover
// session permit (and vice versa)
VOID _app_state_revokeapp (
	_In_ ULONG app_hash
);

// T005: re-deploy all session decisions (rule-apply point — the full
// apply wipes every provider filter)
VOID _app_state_applyall (
	_In_opt_ HWND hwnd
);

// T005: drop stale filter guids after a provider-wide teardown (the
// decision records stay and re-deploy on the next install)
VOID _app_state_clearfilters (VOID);

// T006: count a novel connection diverted while a prompt was visible
VOID _app_state_holdpending (
	_In_ ULONG app_hash
);

// T006: clear the app's held-pending count (a decision now covers it)
VOID _app_state_releasepending (
	_In_ ULONG app_hash
);

// T006: total held-pending connections across apps (tray/status surface)
ULONG _app_state_getheldtotal (VOID);
