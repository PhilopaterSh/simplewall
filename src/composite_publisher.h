// composite_publisher: Authenticode publisher rules (FR-03, SEC-02, DEC-05).
// Signer-hash anchors + materialized per-path PERMIT filters, re-validated
// under WinVerifyTrust at three points (prompt time, the FileMonitor
// 10-minute re-hash loop, rule-apply); lazily bound at connection when a
// new path matches an existing anchor (cached per path+mtime); a signer
// that no longer validates is revoked and logged (drop-out); self-signed
// binaries never qualify. The anchor store is in-memory this round —
// namespaced sidecar persistence lands with T009 (composite_state.h,
// DATA-01); profile.xml is never touched.

#pragma once

#include <windows.h>

#include "main.h"

// config key (namespaced, DEC-09)
#define COMPOSITE_CONFIG_PUBLISHER L"IsCompositePublishersEnabled"

VOID _app_publisher_initialize (VOID);

VOID _app_publisher_uninitialize (VOID);

// T003 tier3 fast path: TRUE when the path already has deployed
// publisher PERMIT filters (no verification performed)
BOOLEAN _app_publisher_ismaterialized (
	_In_ LPCWSTR path
);

// T003 tier3 full check (FR-03 lazy binding): verifies the binary's
// signer (cached per path+mtime) and, when an anchor for that signer
// exists, lazily adds the path to the anchor and materializes its
// PERMIT filters. Self-signed binaries never qualify.
BOOLEAN _app_publisher_istiercovered (
	_In_ PITEM_APP ptr_app
);

// T004 menu gate: TRUE when the binary is signature-verified AND not
// self-signed (the "Always for publisher" item is only offered then)
BOOLEAN _app_publisher_isavailable (
	_In_ ULONG app_hash
);

// T004 prompt-time hook: verify the file and refresh the per-path+mtime
// signer cache (pre-warmed from the popup's signature resolution queue)
BOOLEAN _app_publisher_capturefile (
	_In_ PR_STRING path
);

// T004: bind the app's binary to its verified signer — stores the
// signer-hash anchor, materializes PERMIT filters for the member paths
// and logs the binding. Refuses self-signed binaries.
BOOLEAN _app_publisher_bind (
	_In_opt_ HWND hwnd,
	_In_ PITEM_APP ptr_app
);

// T004 FileMonitor re-validation (10-minute cadence): re-verify every
// bound path, revoke (and log) when the signer no longer validates
VOID _app_publisher_revalidate (VOID);

// T004 rule-apply point: re-validate, then (re-)materialize every valid
// anchor member (the full apply wipes every provider filter)
VOID _app_publisher_applyall (
	_In_opt_ HWND hwnd
);

// T004: drop stale filter guids after a provider-wide teardown
VOID _app_publisher_clearfilters (VOID);
