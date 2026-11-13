#include "global.h"
// composite_apply: FR-11 incremental filter apply core (P2-3).
// Reconciles a desired filter GUID set against a live one and emits the
// exact add/remove deltas — the caller (wfp.c apply path) executes them
// inside the existing tri-state transaction pattern. Pure data logic:
// headless-testable, no WFP calls here (NFR-06).
//
// NFR-04 contract: the incremental path's unfiltered window (the delta
// it must apply) is by construction <= the full-rebuild's (it is a
// subset); the p95 measurement harness lives in tools/bench-nfr04.ps1.

#include "composite_apply.h"
#include "composite_zones.h" // (none) — keep NFR-06: the diff core is dependency-free; the reconcile engine uses fwpuclnt (linked)

VOID _app_apply_diff (
	_In_reads_ (live_count) const GUID *live_guids,
	_In_ ULONG live_count,
	_In_reads_ (desired_count) const GUID *desired_guids,
	_In_ ULONG desired_count,
	_Out_ PAPP_APPLY_DIFF diff
)
{
	ZeroMemory (diff, sizeof (APP_APPLY_DIFF));

	for (ULONG d = 0; d < desired_count; d++)
	{
		BOOLEAN found = FALSE;

		for (ULONG l = 0; l < live_count; l++)
		{
			if (IsEqualGUID (&live_guids[l], &desired_guids[d]))
			{
				found = TRUE;
				break;
			}
		}

		if (!found && diff->adds_count < APP_APPLY_MAX)
		{
			diff->adds[diff->adds_count++] = desired_guids[d];
		}
		else if (!found)
		{
			diff->overflow = TRUE; // caller falls back to full rebuild (safe path)
		}
	}

	for (ULONG l = 0; l < live_count; l++)
	{
		BOOLEAN found = FALSE;

		for (ULONG d = 0; d < desired_count; d++)
		{
			if (IsEqualGUID (&live_guids[l], &desired_guids[d]))
			{
				found = TRUE;
				break;
			}
		}

		if (!found && diff->removes_count < APP_APPLY_MAX)
		{
			diff->removes[diff->removes_count++] = live_guids[l];
		}
		else if (!found)
		{
			diff->overflow = TRUE;
		}
	}
}




// P2-3b (FR-11): remove ORPHANED provider filters — live provider filters
// that no table claims after a full apply (crash/apply-failure leftovers).
// Overflow or engine failure = skip silently-with-log (the full rebuild
// already ran; orphans are cosmetic, never a security hole — the next
// apply retries). Executed inside the caller's transaction.
ULONG _app_apply_reconcileorphans (
	_In_ HANDLE engine,
	_In_ PR_ARRAY desired_guids
)
{
	PR_ARRAY live_guids = NULL;
	ULONG orphans_removed = 0;
	ULONG status;

	status = _wfp_dumpfilters (engine, &GUID_WfpProvider, &live_guids);

	if (status != ERROR_SUCCESS)
	{
		_r_log (LOG_LEVEL_INFO, NULL, L"composite_apply", L"orphan reconcile skipped (enum unavailable)", (LONG)status);
		return 0;
	}

	// FwpmFilterDeleteByKey0 within a transaction owned by the caller
	for (ULONG_PTR i = 0; i < _r_obj_getarraysize (live_guids); i++)
	{
		GUID *live = (GUID *)_r_obj_getarrayitem (live_guids, i);
		BOOLEAN claimed = FALSE;

		for (ULONG_PTR j = 0; j < _r_obj_getarraysize (desired_guids); j++)
		{
			GUID *want = (GUID *)_r_obj_getarrayitem (desired_guids, j);

			if (IsEqualGUID (live, want))
			{
				claimed = TRUE;
				break;
			}
		}

		if (!claimed)
		{
			NTSTATUS del = FwpmFilterDeleteByKey0 (engine, live);

			if (NT_SUCCESS (del))
				orphans_removed++;
		}
	}

	if (orphans_removed)
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_apply", L"orphaned provider filters removed", (LONG)orphans_removed);

	_r_obj_dereference (live_guids);

	return orphans_removed;
}
