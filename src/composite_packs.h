// composite_packs: signed rule packs (FR-08, SEC-01, DATA-02).
// pack.json + detached signature (ECDSA P-256, Round-2 verification core)
// verified against the embedded public key BEFORE any rule parses; key-id
// + monotonic version with anti-rollback via pack_watermarks.json
// (non-rebuildable); unit enable/disable/update with exact filter delta;
// sidecar state hash-checked at load. Implemented in T008-T009.

#pragma once

#include <windows.h>

// import (and verify + enable) a pack from a directory containing
// pack.json + pack.sig; refuses tampered/unsigned/rolled-back packs
NTSTATUS _app_packs_import (
	_In_ LPCWSTR pack_dir
);

BOOLEAN _app_packs_isenabled (
	_In_ LPCWSTR pack_id
);

// disable an enabled pack: exact filter delta removal + state update
NTSTATUS _app_packs_disable (
	_In_ LPCWSTR pack_id
);

// startup consistency: sidecar hash-check; corrupt state = packs refuse
// until re-confirmed (never silently rebuilt — DATA-02)
VOID _app_packs_startupcheck (
	VOID
);
