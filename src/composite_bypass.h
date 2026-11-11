// composite_bypass: T033b (FR-13) bypass detection core.
// Detects traffic to KNOWN external resolver endpoints (bypassing the
// owned local resolver) and emits pack-schema block rules as DATA (the
// signed-pack machinery consumes them — no hardcoded filters, FR-08
// reuse). Well-known public-resolver networks ship as a static starter
// list; the owned resolver (127.0.0.1) and the loopback range are
// always exempt. Dependency-free (NFR-06 headless testing).

#pragma once

#include <windows.h>

#define BYPASS_MAX_ENDPOINTS 0x40

typedef struct _BYPASS_ENDPOINT
{
	ULONG start; // network (host byte order)
	ULONG end;   // range end
	USHORT port; // 53 or 853; 0 = any
	WCHAR name[64]; // resolver name for the log/rules-as-data
} BYPASS_ENDPOINT, *PBYPASS_ENDPOINT;

// seed the detector with the well-known public resolver networks
VOID _app_bypass_seeddefaults (VOID);

// add a custom endpoint to the detector (rules-as-data extensions)
BOOLEAN _app_bypass_addendpoint (
	_In_ ULONG start,
	_In_ ULONG end,
	_In_ USHORT port,
	_In_ LPCWSTR name
);

// verdict: TRUE when (addr, port) matches a registered external
// resolver endpoint (loopback is always exempt — the owned resolver
// lives there)
BOOLEAN _app_bypass_isresolvertraffic (
	_In_ ULONG addr,
	_In_ USHORT port
);

// emit pack-schema rule entries for every registered endpoint (JSON
// fragments, FR-08 schema: {"address": ..., "port": ..., "protocol":
// "udp", "direction": "out"}); returns the emitted rule count
ULONG _app_bypass_emitpackrules (
	_Out_writes_ (buffer_chars) WCHAR *buffer,
	_In_ ULONG buffer_chars
);

ULONG _app_bypass_count (VOID);
