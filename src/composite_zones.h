// composite_zones: FR-07 blocklist engine (P2-4).
// Sorted (start, end) UINT32 range arrays per zone with binary-search
// verdicts, replacing per-IP filter explosion for pack blocklists:
// >=2M entries per zone, >=32 zones, IPv4 first (IPv6 ranges struct-
// ready; same verdicts as the per-IP filter path by construction —
// a zone query is the union of the same CIDR ranges the filters
// represented). Headless-testable: no WFP, no elevation (NFR-06).

#pragma once

#include <windows.h>

#define ZONES_MAX 32
#define ZONES_MAX_ENTRIES 0x200000 // 2M ranges per zone (FR-07)

typedef struct _ZONE_RANGE
{
	ULONG start; // inclusive, host byte order
	ULONG end;   // inclusive
} ZONE_RANGE, *PZONE_RANGE;

typedef struct _ZONE_SET
{
	ZONE_RANGE ranges[ZONES_MAX_ENTRIES];
	ULONG count;      // sorted by start, non-overlapping (coalesced)
	WCHAR id[64];     // zone name (pack id / "internal")
} ZONE_SET, *PZONE_SET;

// verdict: TRUE when ip (host byte order) falls inside any range
BOOLEAN _app_zones_contains (
	_In_ const PZONE_SET zone,
	_In_ ULONG ip
);

// insert a CIDR range (host byte order) keeping the set sorted +
// coalesced; returns FALSE on overflow (zone full)
BOOLEAN _app_zones_insert (
	_Inout_ PZONE_SET zone,
	_In_ ULONG start,
	_In_ ULONG end
);

// parse one CIDR line "a.b.c.d/len" (or bare IP /32) into a range; IPv6
// literals are recognized and counted (struct-ready) but return FALSE
// with *is_ipv6 = TRUE — v6 wiring is the follow-up round
BOOLEAN _app_zones_parsecidr (
	_In_ LPCWSTR line,
	_Out_ ULONG *start,
	_Out_ ULONG *end,
	_Out_ BOOLEAN *is_ipv6
);

// load a zone from a newline-separated CIDR text block (UTF-16)
ULONG _app_zones_load (
	_Inout_ PZONE_SET zone,
	_In_ LPCWSTR cidr_text
);
