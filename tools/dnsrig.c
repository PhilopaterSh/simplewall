//
// tools/dnsrig.c — fail-closed DNS test rig for the fork's update-feed
// verification (docs/specs/tooling/design.md r3, FR-03/FR-04/FR-08;
// DEC-04, DEC-08, DEC-10).
//
// Attribution (NFR-01, DEC-06): the wire-format approach follows the
// MIT-licensed concept lineage of Crypt0s/FakeDns
// (https://github.com/Crypt0s/FakeDns — dormant since 2020) and
// hupe1980/fakedns (https://github.com/hupe1980/fakedns, PyPI, MIT);
// this implementation is C + vendored routine (vendor/routine) only, no
// third-party code. Logic-parity target: tools/dnsrig.py (transition
// reference, retires once this binary passes the same acceptance
// scenarios; DEC-08).
//
// Why the rig exists (decision matrix, design r2 MAJOR-6): a hosts-file
// edit is SIMPLER for a pure positive redirect (Windows resolver consults
// hosts before DNS). The rig's added value: NXDOMAIN-by-default for every
// OTHER name (fail-closed pollution control hosts cannot express),
// per-query transcript logging, resolver-level control for future phases.
//
// Wiring prerequisites (design r2): the guest adapter's DNS must point at
// the rig (or a hosts edit must be applied), AND the feed server's root
// certificate must be installed in the guest trust store — otherwise
// WinHTTP fails closed at TLS (which is itself a valid fail-closed
// assertion).
//
// Deliberate limits (FR-03, mirrored from dnsrig.py):
//   * UDP only — TCP is DELIBERATELY NEVER BOUND: A answers never
//     truncate, so a client that retries over TCP fails closed. This is
//     documented fail-closed behavior, not an omission.
//   * OPT (EDNS0, type 41) records are tolerated and ignored.
//   * NXDOMAIN default policy — the rig is NEVER a recursive resolver
//     (upstream leaks would pollute the test).
//   * QR-bit-set packets (responses) are dropped, never served.
//   * only IN (class 1) A (type 1) questions are answered; mapped names
//     get a 60 s TTL A record with a 0xC00C compression pointer to the
//     question name; unknown names get NXDOMAIN (rcode 3).
//
// Config (mirror of the python [rig]/[mappings] ini layout):
// GetPrivateProfile* against a caller-supplied ini — [rig] bind/port;
// [mappings] name=ip lines (GetPrivateProfileSectionW). Fail-closed:
// missing ini, invalid port, or an invalid mapping value refuses to start
// (SEC-02; the python version accepted bad IPs and crashed on the first
// query — the C rig validates at load).
//
// Self-test mode (FR-04/AS12/AS7): `-selftest` spins an ephemeral
// in-process server thread on loopback, fires three raw loopback queries
// and asserts (1) mapped name answered rcode 0, (2) unknown name
// NXDOMAIN rcode 3, (3) EDNS0/OPT tolerated. Prints PASS/FAIL lines
// exactly like `python tools/dnsrig.py --self-test` and exits 0/1.
// CI-runnable: no sandbox, no admin, no network beyond loopback.
//
// Usage (routine getopt: one or two leading dashes both accepted):
//   dnsrig --config dnsrig.ini     (python: --config)
//   dnsrig --selftest              (python: --self-test)
//
// Build (DEC-10): tools/dnsrig.vcxproj -> bin\64\dnsrig.exe; Console
// subsystem, APP_CONSOLE bootstrap, wmain entry; console output goes ONLY
// through tool_out_format (routine) — never printf.
//

#include "routine.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <wchar.h>

#include <stdarg.h>
#include <wchar.h>

#pragma comment(lib, "ws2_32.lib")

//
// CI/pipes: the routine console writer (WriteConsoleW on the PEB stdout
// handle) silently no-ops on non-console handles - mirror preflight's
// out_write: real console gets WriteConsoleW; pipe/file gets UTF-8
// WriteFile (process-audit lesson: invisible CI output = undiagnosable
// failures; run 42381287177 failed blind).
//
static VOID out_write (LPCWSTR string, ULONG_PTR length)
{
	HANDLE hconsole;
	ULONG mode;
	ULONG chars = (ULONG)(length / sizeof (WCHAR));
	BOOL console_written = FALSE;

	hconsole = NtCurrentPeb ()->ProcessParameters->StandardOutput;

	if (hconsole && hconsole != INVALID_HANDLE_VALUE)
	{
		console_written = (GetConsoleMode (hconsole, &mode) != FALSE) &&
			(WriteConsoleW (hconsole, string, chars, NULL, NULL) != FALSE) &&
			(WriteConsoleW (hconsole, L"\r\n", 2, NULL, NULL) != FALSE);
	}

	if (console_written)
		return;

	{
		PCHAR buffer;
		INT buffer_length;
		DWORD written = 0;
		static const CHAR newline[] = "\n";

		if (!hconsole || hconsole == INVALID_HANDLE_VALUE)
			hconsole = GetStdHandle (STD_OUTPUT_HANDLE);

		buffer_length = WideCharToMultiByte (CP_UTF8, 0, string, (INT)chars, NULL, 0, NULL, NULL);

		if (buffer_length > 0)
		{
			buffer = (PCHAR)_r_mem_allocate ((SIZE_T)buffer_length);

			if (WideCharToMultiByte (CP_UTF8, 0, string, (INT)chars, buffer, buffer_length, NULL, NULL) > 0)
				WriteFile (hconsole, buffer, (DWORD)buffer_length, &written, NULL);

			_r_mem_free (buffer);
		}

		WriteFile (hconsole, newline, (DWORD)(RTL_NUMBER_OF (newline) - 1), &written, NULL);
	}
}

static VOID tool_out_format (LPCWSTR format, ...)
{
	WCHAR buffer[2048];
	va_list args;

	va_start (args, format);
	_vsnwprintf_s (buffer, RTL_NUMBER_OF (buffer), _TRUNCATE, format, args);
	buffer[RTL_NUMBER_OF (buffer) - 1] = UNICODE_NULL;
	va_end (args);

	out_write (buffer, wcslen (buffer) * sizeof (WCHAR));
}

//
// DNS wire constants
//

#define RIG_HEADER_LENGTH 12 // fixed DNS header
#define RIG_DATAGRAM_MAX 4096U // mirrors python recvfrom(4096)
#define RIG_REPLY_MAX 512 // header + max question + A answer, with slack
#define RIG_TTL 60 // seconds (parity: python build_response)
#define RIG_TYPE_A 1U
#define RIG_CLASS_IN 1U
#define RIG_TYPE_OPT 41U // EDNS0 pseudo-record, tolerated and ignored
#define RIG_FLAG_QR 0x8000U // response bit — a rig never serves responses
#define RIG_RCODE_NOERROR 0U
#define RIG_RCODE_NXDOMAIN 3U
#define RIG_QNAME_MAX 256 // characters
#define RIG_SECTION_CAPACITY_MIN 65536 // [mappings] buffer, in WCHARs
#define RIG_SECTION_CAPACITY_MAX 4194304

// qname parse outcome (python parse_qname raises ValueError with these notes)
typedef enum _RIG_QNAME_RESULT
{
	RigQnameOk,
	RigQnameTruncated, // "truncated qname"
	RigQnamePointer, // "compression pointer in query"
} RIG_QNAME_RESULT;

//
// Rig configuration (mirror of python Rig)
//

typedef struct _RIG_MAPPING
{
	PR_STRING name; // lowercased name (parity: python {k.lower(): v})
	PR_STRING value; // dotted-quad string as configured
	IN_ADDR addr; // validated network-order address
} RIG_MAPPING;

typedef struct _RIG_CONFIG
{
	RIG_MAPPING *mappings;
	ULONG count;
} RIG_CONFIG;

typedef struct _RIG_SELFTEST_CONTEXT
{
	SOCKET sock;
	HANDLE stop_event;
	RIG_CONFIG rig;
	volatile LONG queries_seen; // r4 diagnostics: server-side visibility (CI run 42382080671)
	volatile LONG replies_sent;
} RIG_SELFTEST_CONTEXT;

//
// helpers
//

VOID _rig_put16 (
	_Out_writes_ (2) PBYTE buf,
	_In_ USHORT value
)
{
	buf[0] = (BYTE)(value >> 8);
	buf[1] = (BYTE)(value);
}

VOID _rig_put32 (
	_Out_writes_ (4) PBYTE buf,
	_In_ ULONG value
)
{
	buf[0] = (BYTE)(value >> 24);
	buf[1] = (BYTE)(value >> 16);
	buf[2] = (BYTE)(value >> 8);
	buf[3] = (BYTE)(value);
}

USHORT _rig_get16 (
	_In_reads_ (2) const PBYTE buf
)
{
	return (USHORT)(((USHORT)buf[0] << 8) | (USHORT)buf[1]);
}

//
// narrow/wide helpers for the ANSI-only winsock conversion APIs
// (inet_pton/inet_ntop take narrow strings; IP literals are ASCII)
//

VOID _rig_ansi_from_wide (
	_In_ LPCWSTR wide,
	_Out_writes_ (ansi_size) PCHAR ansi,
	_In_ ULONG ansi_size
)
{
	ULONG i = 0;

	for (; wide[i] && i + 1 < ansi_size; i++)
		ansi[i] = (CHAR)wide[i];

	ansi[i] = '\0';
}

VOID _rig_wide_from_ansi (
	_In_ LPCSTR ansi,
	_Out_writes_ (wide_size) LPWSTR wide,
	_In_ ULONG wide_size
)
{
	ULONG i = 0;

	for (; ansi[i] && i + 1 < wide_size; i++)
		wide[i] = (WCHAR)(BYTE)ansi[i];

	wide[i] = UNICODE_NULL;
}

//
// parse a question name starting at *offset (python parse_qname).
// rejects compression pointers in queries and runs past the datagram end.
//
RIG_QNAME_RESULT _rig_parse_qname (
	_In_reads_ (length) const PBYTE data,
	_In_ INT length,
	_Inout_ PINT offset,
	_Out_writes_ (qname_size) LPWSTR qname,
	_In_ ULONG qname_size
)
{
	ULONG idx = 0;
	INT off = *offset;

	qname[0] = UNICODE_NULL;

	while (off < length)
	{
		BYTE label_len = data[off];

		if (label_len == 0)
		{
			*offset = off + 1;
			return RigQnameOk;
		}

		// compression pointer: reject queries with them (clients don't send these)
		if (label_len & 0xC0)
			return RigQnamePointer;

		if (off + 1 + label_len > length)
			return RigQnameTruncated;

		if (idx + label_len + 2 > qname_size)
			return RigQnameTruncated; // treat an oversized name as truncated

		if (idx)
			qname[idx++] = L'.';

		for (BYTE i = 0; i < label_len; i++)
			qname[idx++] = (WCHAR)data[off + 1 + i];

		off += 1 + label_len;
	}

	return RigQnameTruncated; // ran off the datagram without a terminator
}

//
// build the NXDOMAIN response (python build_nxdomain): QR=1 AA=1 RCODE=3,
// questions not echoed, no answers.
//
ULONG _rig_build_nxdomain (
	_Out_writes_ (RIG_HEADER_LENGTH) PBYTE reply,
	_In_ USHORT qid
)
{
	_rig_put16 (reply + 0, qid);
	_rig_put16 (reply + 2, (USHORT)(0x8400 | RIG_RCODE_NXDOMAIN)); // 0x8403
	_rig_put16 (reply + 4, 0); // qdcount
	_rig_put16 (reply + 6, 0); // ancount
	_rig_put16 (reply + 8, 0); // nscount
	_rig_put16 (reply + 10, 0); // arcount

	return RIG_HEADER_LENGTH;
}

//
// build the mapped IN A response (python build_response): QR=1 AA=1
// RCODE=0, question echoed, one answer with a 0xC00C pointer to the
// question name, 60 s TTL, 4-byte A record. returns 0 on overflow.
//
ULONG _rig_build_response (
	_Out_writes_bytes_ (reply_size) PBYTE reply,
	_In_ ULONG reply_size,
	_In_ USHORT qid,
	_In_ LPCWSTR qname,
	_In_ USHORT qtype,
	_In_ const IN_ADDR *addr
)
{
	ULONG pos = RIG_HEADER_LENGTH;
	ULONG qlength = (ULONG)_r_str_getlength (qname);
	ULONG i;

	if (RIG_HEADER_LENGTH + qlength + 4 + 2 + 16 > reply_size)
		return 0; // cannot fit

	// header: QR=1, AA=1, RCODE=0; one question, one answer
	_rig_put16 (reply + 0, qid);
	_rig_put16 (reply + 2, 0x8400);
	_rig_put16 (reply + 4, 1); // qdcount
	_rig_put16 (reply + 6, 1); // ancount
	_rig_put16 (reply + 8, 0); // nscount
	_rig_put16 (reply + 10, 0); // arcount

	// question (echoed as parsed, original case)
	i = 0;

	while (i < qlength)
	{
		ULONG start = i;
		ULONG label_len;

		while (i < qlength && qname[i] != L'.')
			i++;

		label_len = i - start;

		if (!label_len || label_len > 63)
			return 0;

		reply[pos++] = (BYTE)label_len;

		for (ULONG j = start; j < i; j++)
			reply[pos++] = (BYTE)qname[j];

		i++; // skip the dot (or exits the loop at the end of the name)
	}

	reply[pos++] = 0; // root terminator

	_rig_put16 (reply + pos, qtype);
	pos += 2;
	_rig_put16 (reply + pos, RIG_CLASS_IN);
	pos += 2;

	// answer: pointer to the question name + A/IN + TTL 60 + rdlength 4
	reply[pos++] = 0xC0;
	reply[pos++] = 0x0C;
	_rig_put16 (reply + pos, RIG_TYPE_A);
	pos += 2;
	_rig_put16 (reply + pos, RIG_CLASS_IN);
	pos += 2;
	_rig_put32 (reply + pos, RIG_TTL);
	pos += 4;
	_rig_put16 (reply + pos, 4); // rdlength
	pos += 2;
	memcpy (reply + pos, &addr->S_un.S_addr, sizeof (addr->S_un.S_addr));
	pos += 4;

	return pos;
}

//
// look up a mapping by qname (case-insensitive; python lowercases both
// sides — equivalent for ASCII names)
//
RIG_MAPPING* _rig_find_mapping (
	_In_ const RIG_CONFIG *rig,
	_In_ LPCWSTR qname
)
{
	for (ULONG i = 0; i < rig->count; i++)
	{
		if (_wcsicmp (qname, rig->mappings[i].name->buffer) == 0)
			return &rig->mappings[i];
	}

	return NULL;
}

//
// per-query handler — behavior mirror of python Rig.handle: produces a
// reply (and its length) plus a transcript note; a zero reply length
// means "no reply" (drop).
//
VOID _rig_handle_query (
	_In_ const RIG_CONFIG *rig,
	_In_reads_ (length) const PBYTE data,
	_In_ INT length,
	_Out_writes_bytes_ (reply_size) PBYTE reply,
	_In_ ULONG reply_size,
	_Out_ PULONG reply_length,
	_Out_writes_ (note_size) LPWSTR note,
	_In_ ULONG note_size
)
{
	USHORT qid;
	USHORT flags;
	USHORT qtype;
	USHORT qclass;
	WCHAR qname[RIG_QNAME_MAX];
	INT offset;
	RIG_QNAME_RESULT result;

	*reply_length = 0;

	if (length < RIG_HEADER_LENGTH)
	{
		_r_str_copy (note, note_size, L"malformed-query");
		return;
	}

	qid = _rig_get16 (data + 0);
	flags = _rig_get16 (data + 2);

	if (flags & RIG_FLAG_QR)
	{
		// QR bit set = response, never served by a rig
		_r_str_copy (note, note_size, L"not-a-query");
		return;
	}

	offset = RIG_HEADER_LENGTH;
	result = _rig_parse_qname (data, length, &offset, qname, RTL_NUMBER_OF (qname));

	if (result != RigQnameOk)
	{
		_r_str_copy (note, note_size, result == RigQnamePointer ? L"compression pointer in query" : L"truncated qname");
		return;
	}

	// qtype/qclass must follow the question name (python would crash on
	// struct.error here; the C rig fails closed instead)
	if (offset + 4 > length)
	{
		_r_str_copy (note, note_size, L"malformed-query");
		return;
	}

	qtype = _rig_get16 (data + offset + 0);
	qclass = _rig_get16 (data + offset + 2);

	if (qtype == RIG_TYPE_OPT)
	{
		// OPT / EDNS0 additional — not a question
		swprintf (note, note_size, L"%s type=%u:%u (OPT ignored)", qname, (unsigned)qclass, (unsigned)qtype);
		return;
	}

	if (qtype != RIG_TYPE_A || qclass != RIG_CLASS_IN)
	{
		// only IN A is served
		*reply_length = _rig_build_nxdomain (reply, qid);
		swprintf (note, note_size, L"%s type=%u:%u -> NXDOMAIN (type not served)", qname, (unsigned)qclass, (unsigned)qtype);
		return;
	}

	RIG_MAPPING *mapping = _rig_find_mapping (rig, qname);

	if (mapping)
	{
		*reply_length = _rig_build_response (reply, reply_size, qid, qname, qtype, &mapping->addr);

		if (*reply_length)
			swprintf (note, note_size, L"%s type=%u:%u -> %s", qname, (unsigned)qclass, (unsigned)qtype, mapping->value->buffer);
		else
			_r_str_copy (note, note_size, L"malformed-query");

		return;
	}

	// unknown names -> NXDOMAIN (default policy)
	*reply_length = _rig_build_nxdomain (reply, qid);
	swprintf (note, note_size, L"%s type=%u:%u -> NXDOMAIN (default policy)", qname, (unsigned)qclass, (unsigned)qtype);
}

//
// UDP server loop (python serve): bind, print the listening line, answer
// queries, log one line per query. never returns on success.
//
INT _rig_serve (
	_In_ const RIG_CONFIG *rig,
	_In_ LPCWSTR bind_addr,
	_In_ USHORT port
)
{
	SOCKADDR_IN local = {0};
	SOCKET sock;
	CHAR peer_a[64];
	WCHAR peer[64];
	WCHAR note[512];
	WCHAR mappings_text[4096];
	CHAR bind_a[64];
	ULONG pos;

	_rig_ansi_from_wide (bind_addr, bind_a, (ULONG)sizeof (bind_a));

	if (inet_pton (AF_INET, bind_a, &local.sin_addr) != 1)
	{
		tool_out_format (L"FAIL: invalid bind address: %s\n", bind_addr);
		return 1;
	}

	local.sin_family = AF_INET;
	local.sin_port = htons (port);

	sock = WSASocketW (AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);

	if (sock == INVALID_SOCKET)
	{
		tool_out_format (L"FAIL: cannot create UDP socket (wsa error %lu)\n", (ULONG)WSAGetLastError ());
		return 1;
	}

	if (bind (sock, (PSOCKADDR)&local, sizeof (local)) == SOCKET_ERROR)
	{
		tool_out_format (L"FAIL: cannot bind udp/%s:%u (wsa error %lu)\n", bind_addr, (ULONG)port, (ULONG)WSAGetLastError ());
		closesocket (sock);
		return 1;
	}

	// listening line (mirror of the python one; mappings rendered as
	// name=value pairs instead of the python dict repr)
	mappings_text[0] = UNICODE_NULL;
	pos = 0;

	for (ULONG i = 0; i < rig->count; i++)
	{
		INT written = _snwprintf (
			mappings_text + pos,
			RTL_NUMBER_OF (mappings_text) - pos,
			L"%s%s=%s",
			i ? L", " : L"",
			rig->mappings[i].name->buffer,
			rig->mappings[i].value->buffer
		);

		if (written < 0)
		{
			pos = RTL_NUMBER_OF (mappings_text) - 1;
			mappings_text[pos] = UNICODE_NULL;
			break;
		}

		pos += (ULONG)written;
	}

	tool_out_format (L"dnsrig listening on udp/%s:%u — mappings: %s default: nxdomain\n", bind_addr, (ULONG)port, mappings_text);

	for (;;)
	{
		BYTE data[RIG_DATAGRAM_MAX];
		BYTE reply[RIG_REPLY_MAX];
		ULONG reply_length;
		SOCKADDR_IN from = {0};
		INT from_length = sizeof (from);
		INT length;

		length = recvfrom (sock, (PCHAR)data, (INT)sizeof (data), 0, (PSOCKADDR)&from, &from_length);

		if (length <= 0)
			continue;

		_rig_handle_query (rig, data, length, reply, sizeof (reply), &reply_length, note, RTL_NUMBER_OF (note));

		if (!inet_ntop (AF_INET, &from.sin_addr, peer_a, sizeof (peer_a)))
			strcpy_s (peer_a, sizeof (peer_a), "?");

		_rig_wide_from_ansi (peer_a, peer, RTL_NUMBER_OF (peer));

		tool_out_format (L"query from %s: %s\n", peer, note);

		if (reply_length)
			sendto (sock, (PCHAR)reply, (INT)reply_length, 0, (PSOCKADDR)&from, from_length);
	}
}

//
// config loading (python: configparser on the same ini layout). all
// failures are fail-closed (SEC-02).
//
BOOLEAN _rig_load_config (
	_In_ LPCWSTR path,
	_Inout_ RIG_CONFIG *rig,
	_Out_writes_ (bind_size) LPWSTR bind,
	_In_ ULONG bind_size,
	_Out_ PUSHORT port
)
{
	WCHAR port_text[16];
	ULONG long_port;
	PWCHAR section;
	ULONG capacity;

	// [rig] bind/port with python's defaults
	GetPrivateProfileStringW (L"rig", L"bind", L"127.0.0.1", bind, (UINT)bind_size, path);
	GetPrivateProfileStringW (L"rig", L"port", L"53", port_text, (UINT)RTL_NUMBER_OF (port_text), path);

	long_port = wcstoul (port_text, NULL, 10);

	if (!long_port || long_port > 65535)
	{
		tool_out_format (L"FAIL: invalid [rig] port: %s\n", port_text);
		return FALSE;
	}

	*port = (USHORT)long_port;

	// [mappings] name=ip lines (GetPrivateProfileSectionW, house style:
	// rapp.c _r_locale_getversion)
	capacity = RIG_SECTION_CAPACITY_MIN;
	section = _r_mem_allocate (capacity * sizeof (WCHAR));

	for (;;)
	{
		BOOLEAN complete = FALSE;

		memset (section, 0, capacity * sizeof (WCHAR));
		GetPrivateProfileSectionW (L"mappings", section, capacity, path);

		// GetPrivateProfileSectionW truncates by null-terminating the very
		// end of the buffer; a complete section has its double-null
		// terminator strictly INSIDE the buffer (the tail is zeroed above).
		for (ULONG i = 0; i + 2 < capacity; i++)
		{
			if (section[i] == UNICODE_NULL && section[i + 1] == UNICODE_NULL)
			{
				complete = TRUE;
				break;
			}
		}

		if (complete)
			break;

		if (capacity >= RIG_SECTION_CAPACITY_MAX)
		{
			_r_mem_free (section);
			tool_out_format (L"FAIL: [mappings] section too large (config: %s)\n", path);
			return FALSE;
		}

		_r_mem_free (section);
		capacity *= 2;
		section = _r_mem_allocate (capacity * sizeof (WCHAR));
	}

	for (ULONG i = 0; i + 1 < capacity && section[i] != UNICODE_NULL; )
	{
		LPWSTR line = section + i;
		ULONG line_length = (ULONG)_r_str_getlength (line);
		LPWSTR eq = wcschr (line, L'=');

		i += line_length + 1;

		if (!eq)
		{
			// python configparser raises ParsingError on malformed lines;
			// the C rig fails closed instead of serving a partial rig
			tool_out_format (L"FAIL: malformed [mappings] line: '%s' (config: %s)\n", line, path);
			_r_mem_free (section);
			return FALSE;
		}

		*eq = UNICODE_NULL;

		LPWSTR name = line;
		LPWSTR value = eq + 1;

		// trim whitespace (python configparser strips around keys/values)
		while (*name == L' ' || *name == L'\t')
			name++;

		while (*value == L' ' || *value == L'\t')
			value++;

		for (ULONG_PTR j = _r_str_getlength (name); j && (name[j - 1] == L' ' || name[j - 1] == L'\t'); j--)
			name[j - 1] = UNICODE_NULL;

		for (ULONG_PTR j = _r_str_getlength (value); j && (value[j - 1] == L' ' || value[j - 1] == L'\t'); j--)
			value[j - 1] = UNICODE_NULL;

		if (!*name || !*value)
		{
			tool_out_format (L"FAIL: empty [mappings] name or value (config: %s)\n", path);
			_r_mem_free (section);
			return FALSE;
		}

		IN_ADDR addr;
		CHAR value_a[64];

		_rig_ansi_from_wide (value, value_a, (ULONG)sizeof (value_a));

		if (inet_pton (AF_INET, value_a, &addr) != 1)
		{
			tool_out_format (L"FAIL: invalid mapping value for '%s': '%s' (config: %s)\n", name, value, path);
			_r_mem_free (section);
			return FALSE; // fail-closed: python crashed here on the first query instead
		}

		// last duplicate wins (python configparser behavior)
		RIG_MAPPING *existing = NULL;

		for (ULONG k = 0; k < rig->count; k++)
		{
			if (_r_str_compare (name, rig->mappings[k].name->buffer, TRUE) == 0)
			{
				existing = &rig->mappings[k];
				break;
			}
		}

		if (existing)
		{
			_r_obj_dereference (existing->value);
			existing->value = _r_obj_createstring (value);
			existing->addr = addr;
			continue;
		}

		// lowercase name (python: {k.lower(): v})
		for (ULONG j = 0; name[j]; j++)
			name[j] = (WCHAR)towlower (name[j]);

		ULONG new_count = rig->count + 1;
		RIG_MAPPING *grown = _r_mem_reallocate (rig->mappings, new_count * sizeof (RIG_MAPPING));

		if (!grown)
		{
			_r_mem_free (section);
			return FALSE;
		}

		rig->mappings = grown;
		rig->count = new_count;

		RIG_MAPPING *mapping = &rig->mappings[rig->count - 1];
		mapping->name = _r_obj_createstring (name);
		mapping->value = _r_obj_createstring (value);
		mapping->addr = addr;
	}

	_r_mem_free (section);
	return TRUE;
}

//
// self-test server thread (python pump): answer loopback queries until
// the stop event is set; the 250 ms poll mirrors python settimeout(0.25).
//
DWORD WINAPI _rig_selftest_thread (
	_In_ PVOID param
)
{
	RIG_SELFTEST_CONTEXT *ctx = param;
	WCHAR note[512];

	while (WaitForSingleObject (ctx->stop_event, 0) != WAIT_OBJECT_0)
	{
		fd_set fds;
		struct timeval tv = {0, 250000}; // 250 ms
		INT selected;

		FD_ZERO (&fds);
		FD_SET (ctx->sock, &fds);

		selected = select (0, &fds, NULL, NULL, &tv);

		if (selected <= 0)
			continue;

		BYTE data[RIG_DATAGRAM_MAX];
		BYTE reply[RIG_REPLY_MAX];
		ULONG reply_length;
		SOCKADDR_IN from = {0};
		INT from_length = sizeof (from);
		INT length = recvfrom (ctx->sock, (PCHAR)data, (INT)sizeof (data), 0, (PSOCKADDR)&from, &from_length);

		if (length <= 0)
			continue;

		// notes are dropped in the self-test pump (python pump ignores them)
		_rig_handle_query (&ctx->rig, data, length, reply, sizeof (reply), &reply_length, note, RTL_NUMBER_OF (note));

		InterlockedIncrement (&ctx->queries_seen);

		if (reply_length)
		{
			sendto (ctx->sock, (PCHAR)reply, (INT)reply_length, 0, (PSOCKADDR)&from, from_length);
			InterlockedIncrement (&ctx->replies_sent);
		}
	}

	return 0;
}

//
// raw loopback query (python raw_query/query): send a prebuilt datagram,
// read the reply, return the rcode.
//
BOOLEAN _rig_selftest_query (
	_In_ USHORT port,
	_In_reads_ (query_length) const PBYTE query,
	_In_ INT query_length,
	_In_ USHORT expect_qid,
	_Out_ PUSHORT out_rcode
)
{
	SOCKADDR_IN addr = {0};
	SOCKET sock;
	BYTE reply[RIG_REPLY_MAX];
	INT length;
	DWORD timeout = 5000; // python settimeout(5)

	addr.sin_family = AF_INET;
	addr.sin_port = htons (port);

	if (inet_pton (AF_INET, "127.0.0.1", &addr.sin_addr) != 1)
		return FALSE;

	sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sock == INVALID_SOCKET)
		return FALSE;

	setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&timeout, sizeof (timeout));

	if (sendto (sock, (PCHAR)query, query_length, 0, (PSOCKADDR)&addr, sizeof (addr)) == SOCKET_ERROR)
	{
		closesocket (sock);
		return FALSE;
	}

	length = recvfrom (sock, (PCHAR)reply, (INT)sizeof (reply), 0, NULL, NULL);

	closesocket (sock);

	if (length < RIG_HEADER_LENGTH || _rig_get16 (reply + 0) != expect_qid)
	{
		*out_rcode = 0xFFFF; // no response marker
		return FALSE;
	}

	*out_rcode = _rig_get16 (reply + 2) & 0x000F;

	return TRUE;
}

//
// build a query datagram (python query()/OPT-tolerance payloads)
//
INT _rig_build_query (
	_Out_writes_bytes_ (buf_size) PBYTE buf,
	_In_ ULONG buf_size,
	_In_ USHORT qid,
	_In_ LPCSTR qname_a,
	_In_ BOOLEAN is_with_opt
)
{
	ULONG pos = RIG_HEADER_LENGTH;
	ULONG name_length = (ULONG)strlen (qname_a);
	ULONG start = 0;
	ULONG i;

	if (RIG_HEADER_LENGTH + name_length + 2 + 4 + (is_with_opt ? 10 : 0) + 1 > buf_size)
		return 0;

	_rig_put16 (buf + 0, qid);
	_rig_put16 (buf + 2, 0x0100); // standard query (parity: python 0x0100)
	_rig_put16 (buf + 4, 1); // qdcount
	_rig_put16 (buf + 6, 0); // ancount
	_rig_put16 (buf + 8, 0); // nscount
	_rig_put16 (buf + 10, is_with_opt ? 1 : 0); // arcount

	for (i = 0; i <= name_length; i++)
	{
		if (i == name_length || qname_a[i] == '.')
		{
			ULONG label_len = i - start;

			if (!label_len || label_len > 63)
				return 0;

			buf[pos++] = (BYTE)label_len;

			for (ULONG j = start; j < i; j++)
				buf[pos++] = (BYTE)qname_a[j];

			start = i + 1;
		}
	}

	buf[pos++] = 0; // root terminator

	_rig_put16 (buf + pos, RIG_TYPE_A);
	pos += 2;
	_rig_put16 (buf + pos, RIG_CLASS_IN);
	pos += 2;

	if (is_with_opt)
	{
		// EDNS0 OPT record (python: b"\x00" + pack(">HHIH", 41, 4096, 0, 0))
		buf[pos++] = 0; // root name
		_rig_put16 (buf + pos, RIG_TYPE_OPT);
		pos += 2;
		_rig_put16 (buf + pos, 4096); // class = UDP payload size
		pos += 2;
		_rig_put32 (buf + pos, 0); // ttl
		pos += 4;
		_rig_put16 (buf + pos, 0); // rdlength
		pos += 2;
	}

	return (INT)pos;
}

//
// self-test mode (python self_test, FR-04): ephemeral in-process server
// thread + loopback queries; CI-runnable without a sandbox or admin.
//
INT _rig_selftest ()
{
	WSADATA wsa = {0};
	RIG_SELFTEST_CONTEXT ctx = {0};
	SOCKADDR_IN local = {0};
	SOCKADDR_IN actual = {0};
	INT actual_length = sizeof (actual);
	HANDLE thread = NULL;
	HANDLE stop_event = NULL;
	BOOLEAN mapped_ok;
	BOOLEAN nxdomain_ok;
	BOOLEAN opt_ok;
	USHORT rcode = 0xFFFF;
	BYTE query[RIG_REPLY_MAX];
	USHORT srv_port;
	INT query_length;

	if (WSAStartup (MAKEWORD (2, 2), &wsa) != 0)
	{
		tool_out_format (L"FAIL: WSAStartup failed (wsa error %lu)\n", (ULONG)WSAGetLastError ());
		return 1;
	}

	// python: Rig({"rig.test": "127.0.0.1"})
	ctx.rig.count = 1;
	ctx.rig.mappings = _r_mem_allocate (sizeof (RIG_MAPPING));

	if (!ctx.rig.mappings)
	{
		WSACleanup ();
		return 1;
	}

	ctx.rig.mappings[0].name = _r_obj_createstring (L"rig.test");
	ctx.rig.mappings[0].value = _r_obj_createstring (L"127.0.0.1");
	ctx.rig.mappings[0].addr.S_un.S_addr = htonl (0x7F000001);

	ctx.sock = WSASocketW (AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);

	if (ctx.sock == INVALID_SOCKET)
	{
		tool_out_format (L"FAIL: cannot create self-test socket (wsa error %lu)\n", (ULONG)WSAGetLastError ());
		_r_obj_dereference (ctx.rig.mappings[0].name);
		_r_obj_dereference (ctx.rig.mappings[0].value);
		_r_mem_free (ctx.rig.mappings);
		WSACleanup ();
		return 1;
	}

	// python: srv.bind(("127.0.0.1", 0)) — ephemeral loopback port
	local.sin_family = AF_INET;
	local.sin_port = 0;
	local.sin_addr.S_un.S_addr = htonl (0x7F000001);

	if (bind (ctx.sock, (PSOCKADDR)&local, sizeof (local)) == SOCKET_ERROR ||
		getsockname (ctx.sock, (PSOCKADDR)&actual, &actual_length) == SOCKET_ERROR)
	{
		tool_out_format (L"FAIL: cannot bind self-test socket (wsa error %lu)\n", (ULONG)WSAGetLastError ());
		closesocket (ctx.sock);
		_r_obj_dereference (ctx.rig.mappings[0].name);
		_r_obj_dereference (ctx.rig.mappings[0].value);
		_r_mem_free (ctx.rig.mappings);
		WSACleanup ();
		return 1;
	}

	srv_port = ntohs (actual.sin_port);

	stop_event = CreateEventW (NULL, TRUE, FALSE, NULL);
	ctx.stop_event = stop_event;

	if (stop_event)
		thread = CreateThread (NULL, 0, &_rig_selftest_thread, &ctx, 0, NULL);

	if (!thread || !stop_event)
	{
		tool_out_format (L"FAIL: cannot start self-test server thread\n");

		if (stop_event)
			CloseHandle (stop_event);

		closesocket (ctx.sock);
		_r_obj_dereference (ctx.rig.mappings[0].name);
		_r_obj_dereference (ctx.rig.mappings[0].value);
		_r_mem_free (ctx.rig.mappings);
		WSACleanup ();
		return 1;
	}

	// (1) mapped name answered (python qid 0x1234)
	query_length = _rig_build_query (query, sizeof (query), 0x1234, "rig.test", FALSE);

	rcode = 0xFFFF; // r4: never print stack garbage as a verdict (CI run 42382080671)
	if (query_length > 0 && _rig_selftest_query (srv_port, query, query_length, 0x1234, &rcode))
		mapped_ok = (rcode == RIG_RCODE_NOERROR);
	else
		mapped_ok = FALSE;

	tool_out_format (L"%s: mapped name answered (rcode=%u) [server saw %lu q / %lu replies]\n", mapped_ok ? L"PASS" : L"FAIL", (ULONG)rcode, (ULONG)ctx.queries_seen, (ULONG)ctx.replies_sent);

	// (2) unknown name NXDOMAIN (python qid 0x1234)
	query_length = _rig_build_query (query, sizeof (query), 0x1234, "unknown.test", FALSE);

	if (query_length > 0 && _rig_selftest_query (srv_port, query, query_length, 0x1234, &rcode))
		nxdomain_ok = (rcode == RIG_RCODE_NXDOMAIN);
	else
		nxdomain_ok = FALSE;

	tool_out_format (L"%s: unknown name NXDOMAIN (rcode=%u)\n", nxdomain_ok ? L"PASS" : L"FAIL", (ULONG)rcode);

	// (3) EDNS0/OPT tolerated (python qid 0x4321)
	query_length = _rig_build_query (query, sizeof (query), 0x4321, "rig.test", TRUE);

	if (query_length > 0 && _rig_selftest_query (srv_port, query, query_length, 0x4321, &rcode))
		opt_ok = (rcode == RIG_RCODE_NOERROR);
	else
		opt_ok = FALSE;

	tool_out_format (L"%s: EDNS0/OPT tolerated\n", opt_ok ? L"PASS" : L"FAIL");

	// teardown (python finally: stop.set(); join; close)
	SetEvent (stop_event);
	WaitForSingleObject (thread, 1000);

	CloseHandle (thread);
	CloseHandle (stop_event);
	closesocket (ctx.sock);

	_r_obj_dereference (ctx.rig.mappings[0].name);
	_r_obj_dereference (ctx.rig.mappings[0].value);
	_r_mem_free (ctx.rig.mappings);

	tool_out_format (L"dnsrig self-test: %s\n", (mapped_ok && nxdomain_ok && opt_ok) ? L"PASS" : L"FAIL");

	WSACleanup ();

	return (mapped_ok && nxdomain_ok && opt_ok) ? 0 : 1;
}

//
// entry (DEC-10): wmain + APP_CONSOLE bootstrap; returns
// ERROR_APP_INIT_FAILURE when the routine bootstrap fails (e.g.
// -help/-clean/-install/-uninstall args).
//
INT wmain (
	_In_ INT argc,
	_In_ WCHAR **argv
)
{
	WSADATA wsa = {0};
	WCHAR config_path[MAX_PATH + 1] = {0};
	WCHAR bind[64];
	USHORT port;
	RIG_CONFIG rig = {0};
	PR_STRING config_value = NULL;

	UNREFERENCED_PARAMETER (argc);
	UNREFERENCED_PARAMETER (argv);

	if (!_r_app_initialize (NULL))
		return ERROR_APP_INIT_FAILURE;

	// -selftest (also accepts python's --self-test spelling)
	if (_r_sys_getopt (_r_sys_getcommandline (), L"selftest", NULL) ||
		_r_sys_getopt (_r_sys_getcommandline (), L"self-test", NULL))
	{
		return _rig_selftest ();
	}

	// --config <ini> (required; python argparse exits 2 on usage errors)
	if (!_r_sys_getopt (_r_sys_getcommandline (), L"config", &config_value) ||
		!config_value || _r_obj_isstringempty2 (&config_value->sr))
	{
		if (config_value)
			_r_obj_dereference (config_value);

		tool_out_format (L"usage: dnsrig --config <ini> | --self-test\n");
		return 2;
	}

	// GetPrivateProfile* resolves relative paths against the Windows
	// directory — resolve against the caller's cwd first (fail-closed).
	if (!GetFullPathNameW (config_value->buffer, (DWORD)RTL_NUMBER_OF (config_path), config_path, NULL))
	{
		tool_out_format (L"FAIL: config not found: %s\n", config_value->buffer);
		_r_obj_dereference (config_value);
		return 1;
	}

	_r_obj_dereference (config_value);

	if (GetFileAttributesW (config_path) == INVALID_FILE_ATTRIBUTES)
	{
		tool_out_format (L"FAIL: config not found: %s\n", config_path);
		return 1;
	}

	if (!_rig_load_config (config_path, &rig, bind, RTL_NUMBER_OF (bind), &port))
	{
		WSACleanup ();
		return 1;
	}

	if (WSAStartup (MAKEWORD (2, 2), &wsa) != 0)
	{
		tool_out_format (L"FAIL: WSAStartup failed (wsa error %lu)\n", (ULONG)WSAGetLastError ());
		return 1;
	}

	// never returns on success
	INT result = _rig_serve (&rig, bind, port);

	WSACleanup ();

	return result;
}
