// composite_ledger: FR-10 audit ledger + FR-12 baseline integrity
// (DATA-03). Implemented P2-1.

#pragma once

#include <windows.h>

// snapshot the live WFAS store into the baseline (call after our own
// applies; the ledger only judges FOREIGN changes)
NTSTATUS _app_ledger_snapshot (
	VOID
);

// diff live vs baseline; returns the foreign delta count (logged per
// delta with policy-managed status)
ULONG _app_ledger_diff (
	VOID
);

// quarantine a foreign rule (disable + marker); policy-managed refuse
NTSTATUS _app_ledger_quarantine (
	_In_ LPCWSTR rule_name
);

// approve: exact restore (re-enable + strip marker)
NTSTATUS _app_ledger_approve (
	_In_ LPCWSTR rule_name
);

// reject: stays disabled; identity flagged (baseline not refreshed)
NTSTATUS _app_ledger_reject (
	_In_ LPCWSTR rule_name
);

// startup integrity: corrupt/missing baseline = rebuild from the live
// store (FR-12 refuse-and-rebuild contract)
VOID _app_ledger_startupcheck (
	VOID
);
