// composite_resolver: P3-C guarded resolver ownership (T033, FR-13).
// Safety contract per design r2: snapshot-before-write, verify-then-
// commit, exact revert, crash-residue restore, never-leave-DNS-broken.
#pragma once

#include <windows.h>

// module-local status: machine write refused without owner confirmation
// (re-call _app_resolver_own with is_confirmed = TRUE)
#define STATUS_RESOLVER_CONFIRM ((NTSTATUS)0xC05D0002L)

// own the machine's DNS (point every interface at the owned resolver);
// resolver_verified must come from a live check; machine write only
// with is_confirmed (opt-in)
NTSTATUS _app_resolver_own (
	_In_ BOOLEAN is_confirmed,
	_In_ BOOLEAN resolver_verified
);

// exact revert from the snapshot
NTSTATUS _app_resolver_release (
	VOID
);

// startup crash-residue check: restore recorded DNS on any restart that
// finds the owned flag set (never-leave-DNS-broken invariant)
VOID _app_resolver_startupcheck (
	VOID
);

BOOLEAN _app_resolver_isowned (
	VOID
);
