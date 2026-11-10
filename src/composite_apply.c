// composite_apply: FR-11 incremental filter apply core (P2-3).
// Reconciles a desired filter GUID set against a live one and emits the
// exact add/remove deltas — the caller (wfp.c apply path) executes them
// inside the existing tri-state transaction pattern. Pure data logic:
// headless-testable, no WFP calls here (NFR-06).
//
// NFR-04 contract: the incremental path's unfiltered window (the delta
// it must apply) is by construction <= the full-rebuild's (it is a
// subset); the p95 measurement harness lives in tools/bench-nfr04.ps1.

#include "composite_apply.h" // dependency-free: pure GUID diff logic (NFR-06 headless testing)

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


