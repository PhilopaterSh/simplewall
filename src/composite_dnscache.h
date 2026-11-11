// composite_dnscache: FR-13 / DATA-04 cache core (T031).
// Dependency-free (pure CRT + Win32 types — NFR-06 headless testing,
// composite_zones.c precedent). DATA-04 ratified numbers: TTL clamp
// floor 17 s / ceiling 86400 s, stale grace 60 s past expiry, CNAME
// chains to depth 8, capacity 64k entries LRU-evicted. The clock is
// INJECTED (now parameter) for deterministic tests.

#pragma once

#include <windows.h>

#define DNS_CACHE_CAPACITY 0x10000    // 64k entries
#define DNS_TTL_FLOOR_SECONDS 17      // DATA-04 given floor
#define DNS_TTL_CEILING_SECONDS 86400 // 1 day ceiling
#define DNS_STALE_GRACE_SECONDS 60    // retention past expiry
#define DNS_CHAIN_DEPTH 8             // CNAME chain cap
#define DNS_DOMAIN_MAX 256

typedef struct _DNS_ENTRY
{
	WCHAR domain[DNS_DOMAIN_MAX];
	WCHAR cname_parent[DNS_DOMAIN_MAX]; // chain link (empty = terminal)
	BYTE addr[16];                      // A (4) or AAAA (16)
	BOOLEAN is_v6;
	BOOLEAN stale;                      // TRUE = past expiry, within grace
	ULONG expires_at;                   // clamped, seconds (injected clock)
	ULONG chain_depth;
	ULONG last_use;                     // LRU
} DNS_ENTRY, *PDNS_ENTRY;

typedef struct _DNS_CACHE
{
	PDNS_ENTRY entries; // heap-allocated lazily on first upsert (68MB static would violate NFR-03)
	ULONG count;
	ULONG capacity;
} DNS_CACHE, *PDNS_CACHE;

VOID _app_dnscache_upsert (
	_In_ LPCWSTR domain,
	_In_reads_bytes_ (is_v6 ? 16 : 4) const BYTE *addr,
	_In_ BOOLEAN is_v6,
	_In_ ULONG ttl_seconds,
	_In_ ULONG now
);

BOOLEAN _app_dnscache_lookup (
	_In_ LPCWSTR domain,
	_In_ ULONG now,
	_Out_ DNS_ENTRY *out_entry
);

BOOLEAN _app_dnscache_linkcname (
	_In_ LPCWSTR child_domain,
	_In_ LPCWSTR parent_domain,
	_In_ ULONG now
);

BOOLEAN _app_dnscache_resolveip (
	_In_reads_bytes_ (is_v6 ? 16 : 4) const BYTE *addr,
	_In_ BOOLEAN is_v6,
	_In_ ULONG now,
	_Out_ WCHAR *out_domain,
	_In_ ULONG out_chars
);

ULONG _app_dnscache_evict (
	_In_ ULONG now
);

ULONG _app_dnscache_count (
	VOID
);
