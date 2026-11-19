#include "global.h"
#include "composite_doh.h"
#include "composite_dnscache.h"

// T034 (FR-14/P3-D): DoH upstream client. WinHTTP handles TLS (schannel,
// full cert validation) — the module only builds/parses DNS wire format.
// The parsed answers upsert into the T031 cache with the DATA-04 clamps.

#pragma comment (lib, "winhttp.lib")

static VOID _app_doh_encodename (
	_In_ LPCWSTR name,
	_Inout_ BYTE *buffer,
	_Inout_ PULONG offset,
	_In_ ULONG buffer_len
)
{
	// labels: length-prefixed, lowercase-insensitive per RFC 1035 3.1
	LPCWSTR p = name;
	LPCWSTR label_start = p;
	ULONG label_len = 0;

	while (TRUE)
	{
		if (*p == L'.' || *p == UNICODE_NULL)
		{
			label_len = (ULONG)(p - label_start);

			if (label_len > 0 && label_len <= 63 && *offset + 1 + label_len < buffer_len)
			{
				buffer[(*offset)++] = (BYTE)label_len;

				for (ULONG i = 0; i < label_len; i++)
					buffer[(*offset)++] = (BYTE)towlower (label_start[i]);
			}

			if (*p == UNICODE_NULL)
				break;

			label_start = p + 1;
		}

		p++;
	}

	if (*offset < buffer_len)
		buffer[(*offset)++] = 0; // root terminator
}

ULONG _app_doh_buildquery (
	_In_ LPCWSTR name,
	_In_ USHORT qtype,
	_Out_writes_ (buffer_len) BYTE *buffer,
	_In_ ULONG buffer_len
)
{
	ULONG offset = 0;

	if (!name || !*name || buffer_len < 16 + wcslen (name))
		return 0;

	// header: full 12 bytes (id=0, flags RD=1, qd=1, an/ns/ar=0) - the
	// test suite caught a 10-byte header that every resolver rejects
	buffer[offset++] = 0;
	buffer[offset++] = 0; // id
	buffer[offset++] = 0x01; // flags high: RD
	buffer[offset++] = 0x00; // flags low
	buffer[offset++] = 0;
	buffer[offset++] = 1; // qdcount = 1
	buffer[offset++] = 0;
	buffer[offset++] = 0; // ancount
	buffer[offset++] = 0;
	buffer[offset++] = 0; // nscount
	buffer[offset++] = 0;
	buffer[offset++] = 0; // arcount

	_app_doh_encodename (name, buffer, &offset, buffer_len);

	if (offset + 4 > buffer_len)
		return 0;

	buffer[offset++] = (BYTE)(qtype >> 8);
	buffer[offset++] = (BYTE)(qtype & 0xFF);
	buffer[offset++] = 0;
	buffer[offset++] = 1; // qclass = IN

	return offset;
}

// skip a (possibly compressed) name starting at offset; returns the
// offset after it, 0 on failure
static ULONG _app_doh_skipname (
	_In_reads_ (msg_len) const BYTE *msg,
	_In_ ULONG msg_len,
	_In_ ULONG offset
)
{
	ULONG guard = 0;

	while (offset < msg_len && guard++ < 128)
	{
		BYTE len = msg[offset];

		if (len == 0)
			return offset + 1;

		if ((len & 0xC0) == 0xC0)
		{
			if (offset + 2 > msg_len)
				return 0;

			return offset + 2; // compression pointer
		}

		offset += 1 + len;
	}

	return 0;
}

ULONG _app_doh_parseanswers (
	_In_reads_ (msg_len) const BYTE *msg,
	_In_ ULONG msg_len,
	_In_ USHORT family,
	_Out_writes_ (max_addrs) BYTE *addrs,
	_In_ ULONG max_addrs,
	_Out_ PULONG min_ttl
)
{
	ULONG offset;
	ULONG qdcount, ancount;
	ULONG found = 0;
	ULONG rdlength;
	ULONG rdata_pos;
	USHORT type, class;
	ULONG ttl;
	BYTE addr_len = family == 1 ? 4 : 16;

	*min_ttl = 0;

	if (msg_len < 12)
		return 0;

	qdcount = ((ULONG)msg[4] << 8) | msg[5];
	ancount = ((ULONG)msg[6] << 8) | msg[7];

	offset = _app_doh_skipname (msg, msg_len, 12); // skip the question name

	if (!offset || offset + 4 > msg_len || qdcount != 1)
		return 0;

	offset += 4; // qtype + qclass

	for (ULONG i = 0; i < ancount && offset + 10 <= msg_len && found < max_addrs; i++)
	{
		offset = _app_doh_skipname (msg, msg_len, offset);

		if (!offset || offset + 10 > msg_len)
			break;

		type = ((USHORT)msg[offset] << 8) | msg[offset + 1];
		class = ((USHORT)msg[offset + 2] << 8) | msg[offset + 3];
		ttl = ((ULONG)msg[offset + 4] << 24) | ((ULONG)msg[offset + 5] << 16) | ((ULONG)msg[offset + 6] << 8) | msg[offset + 7];
		rdlength = ((ULONG)msg[offset + 8] << 8) | msg[offset + 9];
		rdata_pos = offset + 10;

		if (rdata_pos + rdlength > msg_len)
			break;

		if (class == 1 && type == family && rdlength == addr_len)
		{
			memcpy (addrs + (found * addr_len), msg + rdata_pos, addr_len);
			found++;

			if (*min_ttl == 0 || ttl < *min_ttl)
				*min_ttl = ttl;
		}

		offset = rdata_pos + rdlength;
	}

	return found;
}

// live DoH: WinHTTP POST application/dns-message (RFC 8484); schannel
// TLS with full validation — no skip flags anywhere
BOOLEAN _app_doh_query (
	_In_ LPCWSTR name,
	_In_ USHORT qtype,
	_In_ LPCWSTR resolver_host,
	_Out_writes_bytes_ (is_v6 ? 16 : 4) BYTE *out_addr,
	_Out_ PBOOLEAN is_v6,
	_Out_ PULONG ttl
)
{
	BYTE query[DOH_MAX_MSG];
	BYTE response[DOH_MAX_MSG];
	BYTE addrs[DOH_MAX_ADDRS * 16];
	ULONG query_len;
	ULONG msg_len;
	ULONG addr_len = qtype == 28 ? 16 : 4;
	ULONG answer_count;
	HINTERNET session = NULL;
	HINTERNET connect = NULL;
	HINTERNET request = NULL;
	BOOLEAN is_success = FALSE;
	DWORD status_code = 0;
	DWORD bytes_read = 0;
	DWORD header_size = sizeof (status_code);
	LPWSTR headers = L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n";

	*out_addr = NULL;
	*is_v6 = FALSE;
	*ttl = 0;

	query_len = _app_doh_buildquery (name, qtype, query, sizeof (query));

	if (!query_len)
		return FALSE;

	session = WinHttpOpen (L"quietwall-composite/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	if (!session)
		goto cleanup;

	connect = WinHttpConnect (session, resolver_host, INTERNET_DEFAULT_HTTPS_PORT, 0);

	if (!connect)
		goto cleanup;

	request = WinHttpOpenRequest (connect, L"POST", L"/dns-query", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

	if (!request)
		goto cleanup;

	// secure defaults: schannel validates the certificate chain + name;
	// no security-skip flags are set anywhere (SEC-01 posture)
	if (!WinHttpSendRequest (request, headers, (DWORD)-1, query, query_len, query_len, 0))
		goto cleanup;

	if (!WinHttpReceiveResponse (request, NULL))
		goto cleanup;

	WinHttpQueryHeaders (request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &header_size, WINHTTP_NO_HEADER_INDEX);

	if (status_code != 200)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_doh", L"resolver returned non-200", (LONG)status_code);
		goto cleanup;
	}

	if (!WinHttpReadData (request, response, sizeof (response), &bytes_read) || bytes_read == 0)
		goto cleanup;

	answer_count = _app_doh_parseanswers (response, bytes_read, qtype, addrs, DOH_MAX_ADDRS, ttl);

	if (!answer_count)
		goto cleanup;

	memcpy (out_addr, addrs, addr_len);
	*is_v6 = qtype == 28;
	is_success = TRUE;

	// feed the T031 cache (DATA-04 clamps apply inside upsert)
	_app_dnscache_upsert (name, out_addr, *is_v6, *ttl, (ULONG)time (NULL));

cleanup:
	if (request)
		WinHttpCloseHandle (request);

	if (connect)
		WinHttpCloseHandle (connect);

	if (session)
		WinHttpCloseHandle (session);

	return is_success;
}
