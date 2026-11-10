// composite_apply: FR-11 incremental apply core (P2-3). Pure decision
// logic: diff desired vs live filter GUID sets; the wfp.c apply path
// executes the emitted deltas inside its existing tri-state transaction
// (it owns the filter bodies and the create/delete calls). overflow =
// delta exceeds the preallocated buffers -> caller falls back to the
// full rebuild (safe path, never a partial apply).
#pragma once

#include <windows.h>

#define APP_APPLY_MAX 0x2000

typedef struct _APP_APPLY_DIFF
{
	GUID adds[APP_APPLY_MAX];     // in desired, not in live -> create
	GUID removes[APP_APPLY_MAX];  // in live, not in desired -> delete
	ULONG adds_count;
	ULONG removes_count;
	BOOLEAN overflow;             // TRUE = fall back to full rebuild
} APP_APPLY_DIFF, *PAPP_APPLY_DIFF;

VOID _app_apply_diff (
	_In_reads_ (live_count) const GUID *live_guids,
	_In_ ULONG live_count,
	_In_reads_ (desired_count) const GUID *desired_guids,
	_In_ ULONG desired_count,
	_Out_ PAPP_APPLY_DIFF diff
);
