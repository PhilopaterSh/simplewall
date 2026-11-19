// composite_doh: T034 (FR-14) DoH upstream client + wire-format core.
// Transport: WinHTTP (system library, NFR-02 clean; schannel TLS with
// full certificate validation — no skips). Wire format: RFC 1035
// (build query / parse answers), RFC 8484 application/dns-message POST.
// Resolver URL lives in config (default Cloudflare). The parsed answers
// feed the T031 cache with the DATA-04 clamps.
// Dependency-free for the wire core (NFR-06 headless testing); WinHTTP
// is used only by the live query path.
#pragma once

#include <windows.h>

#define DOH_MAX_ADDRS 16
#define DOH_MAX_MSG 4096

// build an RFC 1035 query (RD=1, single question) for name/qtype
// (qtype: 1 = A, 28 = AAAA). Returns the message length, 0 on failure
ULONG _app_doh_buildquery (
	_In_ LPCWSTR name,
	_In_ USHORT qtype,
	_Out_writes_ (buffer_len) BYTE *buffer,
	_In_ ULONG buffer_len
);

// parse an RFC 1035 response: extract A (1) or AAAA (28) answers
// (family selects which). Returns the answer count
ULONG _app_doh_parseanswers (
	_In_reads_ (msg_len) const BYTE *msg,
	_In_ ULONG msg_len,
	_In_ USHORT family,
	_Out_writes_ (max_addrs) BYTE *addrs, // 4 or 16 bytes per entry
	_In_ ULONG max_addrs,
	_Out_ PULONG min_ttl
);

// live DoH query (WinHTTP POST application/dns-message); returns TRUE
// and the first A/AAAA address on success
BOOLEAN _app_doh_query (
	_In_ LPCWSTR name,
	_In_ USHORT qtype,
	_In_ LPCWSTR resolver_host,
	_Out_writes_bytes_ (is_v6 ? 16 : 4) BYTE *out_addr,
	_Out_ PBOOLEAN is_v6,
	_Out_ PULONG ttl
);
