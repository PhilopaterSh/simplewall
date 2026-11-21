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

// DEC-11 query API (GUI Packs page): enumerate enabled/known packs
ULONG _app_packs_querycount (
	VOID
);

BOOLEAN _app_packs_query (
	_In_ ULONG index,
	_Out_writes_ (id_chars) WCHAR *id_buffer,
	_In_ ULONG id_chars,
	_Out_writes_ (ver_chars) WCHAR *version_buffer,
	_In_ ULONG ver_chars,
	_Out_ PBOOLEAN is_enabled
);

// additive GUI helper (r4 G2-M3, same _app_audit_probe precedent): the
// deployed-filter count of the row _app_packs_query returned (from the
// same mtime-checked sidecar snapshot — no extra file I/O)
ULONG _app_packs_queryfiltercount (
	_In_ ULONG index
);

// TEST INSTRUMENTS (r4 G2-M1; NFR-06): real-serializer fixtures for
// the packstate sidecar. Used only by -gui-selftest.
VOID _app_packs_selftest_getstatepath (
	_Out_ PR_STRING_PTR out_path
);

BOOLEAN _app_packs_selftest_writestate (
	_In_ LPCWSTR pack_id,
	_In_ LPCWSTR version,
	_In_ ULONG filter_count
);
