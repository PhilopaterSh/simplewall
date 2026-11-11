// composite_dnscache: FR-13 / DATA-04 cache core (T031).
// Dependency-free (pure CRT + Win32 types — NFR-06 headless testing,
// composite_zones.c precedent). TTL clamp per the ratified DATA-04
// numbers: floor 17 s, ceiling 86400 s; stale grace 60 s past expiry
// (queryable with a stale flag) then hard-evict; CNAME chains to depth
// 8; capacity 64k entries, LRU eviction (hard-evict expired-past-grace
// first, then least-recently-used).
//
// The clock is INJECTED (now parameter) so tests are deterministic
// without sleeping — the production caller passes unix time.

#include "composite_dnscache.h"

static DNS_CACHE g_cache = {0, 0, 0}; // single instance (SEC-05: in-process); entries heap-allocated lazily

static BOOLEAN _app_dnscache_ensurecapacity (VOID)
{
	if (g_cache.entries)
		return TRUE;

	g_cache.entries = (PDNS_ENTRY)HeapAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY, DNS_CACHE_CAPACITY * sizeof (DNS_ENTRY));

	return g_cache.entries != NULL;
}

static ULONG g_now; // last observed clock (for LRU tie-breaks)

static ULONG _app_dnscache_hashdomain (
	_In_ LPCWSTR domain
)
{
	ULONG hash = 0x811C9DC5;

	for (LPCWSTR p = domain; *p; p++)
	{
		hash ^= (ULONG)(*p | 0x20); // case-insensitive
		hash *= 0x01000193;
	}

	return hash;
}

static LONG _app_dnscache_find (
	_In_ LPCWSTR domain
)
{
	for (ULONG i = 0; i < g_cache.count; i++)
	{
		if (_wcsicmp (g_cache.entries[i].domain, domain) == 0)
			return (LONG)i;
	}

	return -1;
}

static VOID _app_dnscache_evictexpired (
	_In_ ULONG now
)
{
	// hard-evict anything past expiry + grace (scan; compaction is fine
	// at this capacity)
	ULONG i = 0;

	while (i < g_cache.count)
	{
		if (now > g_cache.entries[i].expires_at + DNS_STALE_GRACE_SECONDS)
		{
			memmove (&g_cache.entries[i], &g_cache.entries[i + 1], (g_cache.count - i - 1) * sizeof (DNS_ENTRY));
			g_cache.count--;
		}
		else
		{
			i++;
		}
	}
}

VOID _app_dnscache_upsert (
	_In_ LPCWSTR domain,
	_In_reads_bytes_ (is_v6 ? 16 : 4) const BYTE *addr,
	_In_ BOOLEAN is_v6,
	_In_ ULONG ttl_seconds,
	_In_ ULONG now
)
{
	LONG index;
	DNS_ENTRY *entry;

	if (!domain || !*domain || !addr)
		return;

	g_now = now;

	_app_dnscache_evictexpired (now);

	if (!_app_dnscache_ensurecapacity ())
		return;

	index = _app_dnscache_find (domain);

	if (index < 0)
	{
		// capacity: evict LRU then retry
		if (g_cache.count >= DNS_CACHE_CAPACITY)
		{
			ULONG oldest = 0;

			for (ULONG i = 1; i < g_cache.count; i++)
			{
				if (g_cache.entries[i].last_use < g_cache.entries[oldest].last_use)
					oldest = i;
			}

			memmove (&g_cache.entries[oldest], &g_cache.entries[oldest + 1], (g_cache.count - oldest - 1) * sizeof (DNS_ENTRY));
			g_cache.count--;
		}

		index = (LONG)g_cache.count++;

		entry = &g_cache.entries[index];

		wcsncpy_s (entry->domain, RTL_NUMBER_OF (entry->domain), domain, _TRUNCATE);
		entry->chain_depth = 0;
		entry->cname_parent[0] = UNICODE_NULL;
	}
	else
	{
		entry = &g_cache.entries[index];
	}

	memcpy (entry->addr, addr, is_v6 ? 16 : 4);
	entry->is_v6 = is_v6;

	// DATA-04 clamp: floor 17 s, ceiling 86400 s
	if (ttl_seconds < DNS_TTL_FLOOR_SECONDS)
		ttl_seconds = DNS_TTL_FLOOR_SECONDS;

	if (ttl_seconds > DNS_TTL_CEILING_SECONDS)
		ttl_seconds = DNS_TTL_CEILING_SECONDS;

	entry->expires_at = now + ttl_seconds;
	entry->stale = FALSE;
	entry->last_use = now;
}

BOOLEAN _app_dnscache_lookup (
	_In_ LPCWSTR domain,
	_In_ ULONG now,
	_Out_ DNS_ENTRY *out_entry
)
{
	LONG index;

	(VOID)now; // API symmetry; expiry comparison uses the caller clock

	g_now = now;

	if (!_app_dnscache_ensurecapacity ())
		return FALSE;

	index = _app_dnscache_find (domain);

	if (index < 0)
		return FALSE;

	memcpy (out_entry, &g_cache.entries[index], sizeof (DNS_ENTRY));

	if (now > out_entry->expires_at)
	{
		if (now > out_entry->expires_at + DNS_STALE_GRACE_SECONDS)
			return FALSE; // past grace: hard-expired (evict lazily)

		out_entry->stale = TRUE; // within grace: queryable but flagged
	}

	out_entry->last_use = now;

	return TRUE;
}

// CNAME chain: link a child domain to its parent (up to DNS_CHAIN_DEPTH
// links); resolve walks the chain to the terminal address
BOOLEAN _app_dnscache_linkcname (
	_In_ LPCWSTR child_domain,
	_In_ LPCWSTR parent_domain,
	_In_ ULONG now
)
{
	LONG index;

	g_now = now;

	if (!_app_dnscache_ensurecapacity ())
		return FALSE;

	index = _app_dnscache_find (child_domain);

	if (index < 0)
		return FALSE;

	if (g_cache.entries[index].chain_depth >= DNS_CHAIN_DEPTH)
		return FALSE; // chain depth cap (DATA-04: 8)

	wcsncpy_s (g_cache.entries[index].cname_parent, RTL_NUMBER_OF (g_cache.entries[index].cname_parent), parent_domain, _TRUNCATE);

	g_cache.entries[index].chain_depth++;

	return TRUE;
}

// resolve an address back to its domain (the Audit-tab surface): walks
// the CNAME chain so the reported domain is the terminal A/AAAA owner
BOOLEAN _app_dnscache_resolveip (
	_In_reads_bytes_ (is_v6 ? 16 : 4) const BYTE *addr,
	_In_ BOOLEAN is_v6,
	_In_ ULONG now,
	_Out_ WCHAR *out_domain,
	_In_ ULONG out_chars
)
{
	if (!g_cache.entries)
		return FALSE;

	for (ULONG i = 0; i < g_cache.count; i++)
	{
		DNS_ENTRY *entry = &g_cache.entries[i];

		if (entry->is_v6 != is_v6)
			continue;

		if (memcmp (entry->addr, addr, is_v6 ? 16 : 4) == 0)
		{
			// walk the CNAME chain to the terminal entry (safety cap =
			// chain depth; a cycle would exceed it and stop)
			LPCWSTR reported = entry->domain;
			ULONG hops = 0;

			while (entry->cname_parent[0] && hops < DNS_CHAIN_DEPTH)
			{
				LONG parent = _app_dnscache_find (entry->cname_parent);

				if (parent < 0)
					break;

				entry = &g_cache.entries[parent];
				reported = entry->domain;
				hops++;
			}

			wcscpy_s (out_domain, out_chars, reported);

			return TRUE;
		}
	}

	return FALSE;
}

ULONG _app_dnscache_evict (
	_In_ ULONG now
)
{
	ULONG before = g_cache.count;

	_app_dnscache_evictexpired (now);

	return before - g_cache.count;
}

ULONG _app_dnscache_count (VOID)
{
	return g_cache.count;
}
