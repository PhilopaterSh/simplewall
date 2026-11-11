#include "composite_bypass.h"
#include <wchar.h>
#include "composite_zones.h" // (reuse candidate only; no WFP)

// T033b starter list: well-known public resolvers (rules-as-data —
// consumed by the signed-pack path, never hardcoded filters). Extend
// via _app_bypass_addendpoint or pack data.
static BYPASS_ENDPOINT g_endpoints[BYPASS_MAX_ENDPOINTS];
static ULONG g_count = 0;

static VOID _app_bypass_add (
	_In_ ULONG start,
	_In_ ULONG end,
	_In_ USHORT port,
	_In_ LPCWSTR name
)
{
	if (g_count >= BYPASS_MAX_ENDPOINTS)
		return;

	g_endpoints[g_count].start = start;
	g_endpoints[g_count].end = end;
	g_endpoints[g_count].port = port;
	wcsncpy_s (g_endpoints[g_count].name, RTL_NUMBER_OF (g_endpoints[g_count].name), name, _TRUNCATE);
	g_count++;
}

VOID _app_bypass_seeddefaults (VOID)
{
	// Cloudflare
	_app_bypass_add (0x01010100, 0x010101FF, 53, L"cloudflare-dns");
	_app_bypass_add (0x01010100, 0x010101FF, 853, L"cloudflare-dns (DoT)");
	_app_bypass_add (0x01010001, 0x01010002, 53, L"1.1.1.1/1.0.0.1 exact");
	// Google
	_app_bypass_add (0x08080808, 0x08080808, 53, L"google-dns");
	_app_bypass_add (0x08080808, 0x08080808, 853, L"google-dns (DoT)");
	_app_bypass_add (0x08080404, 0x08080404, 53, L"google-dns-2");
	// Quad9
	_app_bypass_add (0x9E9E9E9E, 0x9E9E9E9E, 53, L"quad9");
	// OpenDNS
	_app_bypass_add (0xD043DCDC, 0xD043DCDC, 53, L"opendns");
	_app_bypass_add (0xD043DCDE, 0xD043DCDE, 53, L"opendns-2");
}

BOOLEAN _app_bypass_addendpoint (
	_In_ ULONG start,
	_In_ ULONG end,
	_In_ USHORT port,
	_In_ LPCWSTR name
)
{
	if (start > end || g_count >= BYPASS_MAX_ENDPOINTS)
		return FALSE;

	_app_bypass_add (start, end, port, name);

	return TRUE;
}

BOOLEAN _app_bypass_isresolvertraffic (
	_In_ ULONG addr,
	_In_ USHORT port
)
{
	// loopback exemption: the OWNED resolver lives there (never flagged)
	if ((addr & 0xFF000000) == 0x7F000000)
		return FALSE;

	for (ULONG i = 0; i < g_count; i++)
	{
		if (addr >= g_endpoints[i].start && addr <= g_endpoints[i].end)
		{
			if (g_endpoints[i].port == 0 || g_endpoints[i].port == port)
				return TRUE;
		}
	}

	return FALSE;
}

ULONG _app_bypass_emitpackrules (
	_Out_writes_ (buffer_chars) WCHAR *buffer,
	_In_ ULONG buffer_chars
)
{
	ULONG written = 0;

	for (ULONG i = 0; i < g_count; i++)
	{
		WCHAR line[256];
		LONG chars;

		ULONG a = g_endpoints[i].start;
		USHORT port = g_endpoints[i].port;
		LPCWSTR proto = (port == 853) ? L"tcp" : L"udp";

		chars = swprintf_s (line, RTL_NUMBER_OF (line),
			L"{\"address\": \"%u.%u.%u.%u\", \"port\": %u, \"protocol\": \"%s\", \"direction\": \"out\", \"name\": \"%s\"},\r\n",
			(a >> 24) & 255, (a >> 16) & 255, (a >> 8) & 255, a & 255,
			port == 0 ? 53 : port, proto, g_endpoints[i].name);

		if (chars <= 0 || (ULONG)chars >= buffer_chars - written)
			break;

		memcpy (buffer + written, line, (SIZE_T)chars * sizeof (WCHAR));
		written += (ULONG)chars;
	}

	if (written)
		buffer[written - 2] = UNICODE_NULL; // strip trailing comma+CRLF

	buffer[written] = UNICODE_NULL;

	return g_count; // rule count emitted
}

ULONG _app_bypass_count (VOID)
{
	return g_count;
}
