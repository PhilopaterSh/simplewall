#include "composite_zones.h" // dependency-free: pure CRT + Win32 types (NFR-06 headless testing)

// FR-07 (P2-4): sorted range-set engine. Design notes:
// - ranges kept sorted by start and COALESCED (touching ranges merge)
//   so the array is minimal and binary search is exact;
// - insert: lower-bound by start, then merge-left/right over the
//   touching window — O(1) append for already-sorted loader input
//   (packs repo emits sorted CIDR blocks), O(n) memmove worst case;
// - verdict: classic binary search with an end-range check.

BOOLEAN _app_zones_contains (
	_In_ const PZONE_SET zone,
	_In_ ULONG ip
)
{
	ULONG low = 0;
	ULONG high = zone->count;

	while (low < high)
	{
		ULONG mid = low + (high - low) / 2;

		if (zone->ranges[mid].end < ip)
			low = mid + 1;
		else if (zone->ranges[mid].start > ip)
			high = mid;
		else
			return TRUE; // start <= ip <= end
	}

	return FALSE;
}

BOOLEAN _app_zones_insert (
	_Inout_ PZONE_SET zone,
	_In_ ULONG start,
	_In_ ULONG end
)
{
	ULONG pos = 0;
	ULONG hi = zone->count;
	ULONG merge_lo;
	ULONG merge_hi;
	ULONG new_start;
	ULONG new_end;
	ULONG i;

	if (start > end)
		return FALSE;

	// lower bound: first range whose start > end
	while (pos < hi)
	{
		ULONG mid = pos + (hi - pos) / 2;

		if (zone->ranges[mid].start <= end)
			pos = mid + 1;
		else
			hi = mid;
	}

	merge_lo = pos;
	merge_hi = pos;

	// extend left: previous range OVERLAPS (prev.end >= start) or
	// TOUCHES (prev.end + 1 == start). A plain >= test would wrongly
	// merge across gaps smaller than prev.end (caught by the scale probe)
	if (merge_lo > 0)
	{
		ULONG prev_end = zone->ranges[merge_lo - 1].end;

		if (prev_end >= start || (prev_end + 1 == start))
			merge_lo--;
	}

	// extend right: next ranges whose start <= end+1 (end==0xFFFFFFFF absorbs)
	while (merge_hi < zone->count && (end == 0xFFFFFFFF || zone->ranges[merge_hi].start <= end + 1))
		merge_hi++;

	if (merge_lo == merge_hi)
	{
		// pure insertion
		if (zone->count >= ZONES_MAX_ENTRIES)
			return FALSE;

		memmove (&zone->ranges[merge_lo + 1], &zone->ranges[merge_lo], (zone->count - merge_lo) * sizeof (ZONE_RANGE));

		zone->ranges[merge_lo].start = start;
		zone->ranges[merge_lo].end = end;
		zone->count++;

		return TRUE;
	}

	// merge [merge_lo, merge_hi) into one range
	new_start = start < zone->ranges[merge_lo].start ? start : zone->ranges[merge_lo].start;
	new_end = end;

	for (i = merge_lo; i < merge_hi; i++)
	{
		if (zone->ranges[i].end > new_end)
			new_end = zone->ranges[i].end;
	}

	zone->ranges[merge_lo].start = new_start;
	zone->ranges[merge_lo].end = new_end;

	if (merge_hi - merge_lo > 1)
	{
		memmove (&zone->ranges[merge_lo + 1], &zone->ranges[merge_hi], (zone->count - merge_hi) * sizeof (ZONE_RANGE));
		zone->count -= (merge_hi - merge_lo - 1);
	}

	return TRUE;
}

BOOLEAN _app_zones_parsecidr (
	_In_ LPCWSTR line,
	_Out_ ULONG *start,
	_Out_ ULONG *end,
	_Out_ BOOLEAN *is_ipv6
)
{
	UCHAR octets[4] = {0};
	ULONG dots = 0;
	ULONG value = 0;
	ULONG prefix = 32;
	ULONG i;

	*start = 0;
	*end = 0;
	*is_ipv6 = FALSE;

	// IPv6 detection: contains ':' — struct-ready (v6 wiring = follow-up)
	if (wcschr (line, L':'))
	{
		*is_ipv6 = TRUE;
		return FALSE;
	}

	// parse a.b.c.d[/prefix]
	for (i = 0; line[i]; i++)
	{
		WCHAR c = line[i];

		if (c >= L'0' && c <= L'9')
		{
			value = value * 10 + (ULONG)(c - L'0');

			if (value > 255)
				return FALSE;
		}
		else if (c == L'.')
		{
			if (dots >= 3)
				return FALSE;

			octets[dots++] = (UCHAR)value;
			value = 0;
		}
		else if (c == L'/')
		{
			octets[dots++] = (UCHAR)value;
			value = 0;

			if (dots != 4)
				return FALSE;

			prefix = 0;

			for (i = i + 1; line[i]; i++)
			{
				if (line[i] < L'0' || line[i] > L'9')
					return FALSE;

				prefix = prefix * 10 + (ULONG)(line[i] - L'0');

				if (prefix > 32)
					return FALSE;
			}

			break;
		}
		else
		{
			return FALSE;
		}
	}

	if (dots == 3)
		octets[dots] = (UCHAR)value;
	else if (dots != 4)
		return FALSE; // 1-2 dots = malformed

	*start = ((ULONG)octets[0] << 24) | ((ULONG)octets[1] << 16) | ((ULONG)octets[2] << 8) | (ULONG)octets[3];

	ULONG host_bits = 32 - prefix;

	if (host_bits == 0)
	{
		*end = *start; // /32: shift-by-32 is UB on x86 — special case
	}
	else if (host_bits == 32)
	{
		*start = 0;
		*end = 0xFFFFFFFF; // /0
	}
	else
	{
		ULONG mask = 0xFFFFFFFF << host_bits;

		*start = (*start & mask);
		*end = (*start | ((1u << host_bits) - 1)); // never shifts by 32
	}

	return TRUE;
}

ULONG _app_zones_load (
	_Inout_ PZONE_SET zone,
	_In_ LPCWSTR cidr_text
)
{
	ULONG loaded = 0;
	LPCWSTR line = cidr_text;
	WCHAR buf[64];

	zone->count = 0;

	while (line && *line)
	{
		LPCWSTR line_end = wcschr (line, L'\n');
		SIZE_T len = line_end ? (SIZE_T)(line_end - line) : wcslen (line);

		if (len && line[len - 1] == L'\r')
			len--;

		if (len > 0 && len < RTL_NUMBER_OF (buf))
		{
			ULONG start;
			ULONG end;
			BOOLEAN is_ipv6;

			memcpy (buf, line, len * sizeof (WCHAR));
			buf[len] = UNICODE_NULL;

			if (_app_zones_parsecidr (buf, &start, &end, &is_ipv6))
			{
				if (_app_zones_insert (zone, start, end))
					loaded++;
			}

			// IPv6/malformed lines are counted by the caller via verdict
			// probes; the loader's contract is: loaded = ranges accepted
		}

		line = line_end ? line_end + 1 : NULL;
	}

	return loaded;
}
