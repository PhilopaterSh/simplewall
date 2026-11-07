//
// tools/feedserver.c — minimal schannel HTTPS/1.1 static server for the
// fork's update-feed root (docs/specs/tooling/design.md r3, FR-06/FR-09;
// DEC-01 -> DEC-08 language unification, DEC-10 build pattern).
//
// Attribution (NFR-01, DEC-06): concept lineage — serving a controlled
// feed root for offline updater tests — follows the signed-feed harness
// conventions established in docs/specs/routine-hardening (the ECDSA
// P-256 feed + detached .sig). No third-party code; C + vendored routine
// (vendor/routine) + OS schannel/crypt32 only. Logic-parity target:
// tools/feedserver.py (transition reference, retires once this binary
// passes the same acceptance scenarios; DEC-08).
//
// CERTIFICATE (approved simplification): PFX only. The python version
// took a PEM cert/key pair; importing a PEM private key in raw C is
// heavy, so the C rig takes a caller-exported .pfx (+ password) via
// PFXImportCertStore (crypt32) and AcquireCredentialsHandle (secur32,
// "Microsoft Unified Security Protocol Provider"). The tester exports
// the PowerShell-generated cert to PFX:
//   New-SelfSignedCertificate -DnsName feed.test
//     -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')
//   Export-PfxCertificate -Cert <cert> -FilePath feed.pfx -Password <pass>
// The guest must trust the PFX root (see design r2 wiring prerequisites);
// the client is WinHTTP/curl against a guest-trusted root, so no server
// name check flags are needed.
//
// Behavior (mirror of feedserver.py):
//   * serves the feed root: VERSION, VERSION.sig, and any artifact URLs
//     the manifest names (subpaths honored; content-type by extension —
//     text/plain for VERSION/VERSION.sig/.txt, application/octet-stream
//     default).
//   * fail-closed (AS13/SEC-02): missing feed pair (VERSION or
//     VERSION.sig) in the root, missing PFX, or a bad PFX password all
//     REFUSE TO START.
//   * no directory listing: "/" (empty path) and any directory target
//     are refused.
//   * no parent-directory traversal: every path is percent-decoded,
//     normalized segment-by-segment and prefix-checked against the root;
//     any ".." popping past the root is refused.
//   * request log line per request (python BaseHTTPRequestHandler shape:
//     `%s - - [%s] "%s" %u -`).
//
// Documented deviations from the python reference (test-rig scope):
//   * one request per connection: responses always carry
//     "Connection: close" and the socket closes after the response —
//     acceptable for a test rig (curl/WinHTTP reconnect per request).
//   * 403 (not python's 404) for directory-listing attempts — the
//     explicit acceptance criterion for the C server; both fail closed.
//   * 30 s per-socket receive/send timeout so a wedged client cannot
//     stall the sequential accept loop (python had no timeout; an
//     improvement, fail-closed).
//   * non-GET methods answer 501 (python do_GET-only behaves the same).
//
// Usage:
//   feedserver --root <feed-dir> --pfx <file.pfx> --password <pass>
//              [--port 443] [--bind 127.0.0.1]
//   (routine getopt: one or two leading dashes both accepted)
//
// Build (DEC-10): tools/feedserver.vcxproj -> bin\64\feedserver.exe;
// Console subsystem, APP_CONSOLE bootstrap, wmain entry; SECURITY_WIN32
// is defined in the vcxproj BEFORE the sspi headers; console output goes
// ONLY through _r_console_writestringformat (routine) — never printf.
//

#include "routine.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <security.h>
#include <subauth.h> // provides UNICODE_STRING for the SCHANNEL_USE_BLACKLISTS block
#define SCHANNEL_USE_BLACKLISTS // expose SCH_CREDENTIALS (modern credential struct)
#include <schannel.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

//
// constants
//

#define FEED_RAW_SIZE 16384 // encrypted receive buffer
#define FEED_PLAIN_SIZE 16384 // plaintext accumulation buffer
#define FEED_TIMEOUT_MS 30000 // per-socket recv/send timeout (fail-closed)
#define FEED_BACKLOG 8
#define FEED_REL_MAX 1024 // normalized relative path, in WCHARs
#define FEED_DEPTH_MAX 64 // path segment count cap
#define FEED_TARGET_MAX 512 // request target, in characters

//
// types
//

typedef struct _FEED_SERVER
{
	LPWSTR root; // absolute feed root (caller cwd-resolved)
	CredHandle cred;
	BOOLEAN have_cred;
	PCCERT_CONTEXT cert; // process-lifetime: schannel paCreds must outlive the credentials
	HCERTSTORE store; // process-lifetime: the cert/key pair lives in this store
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key_handle; // process-lifetime: attached to the cert via CERT_KEY_CONTEXT
} FEED_SERVER;

typedef struct _FEED_CONN
{
	SOCKET sock;
	CredHandle cred;
	CtxtHandle ctx;
	BOOLEAN have_ctx;
	ULONG seqno; // EncryptMessage sequence
	SecPkgContext_StreamSizes sizes;
	PBYTE raw; // encrypted bytes received from the wire
	ULONG raw_size;
	ULONG raw_len;
	PBYTE send; // encrypted packet staging (header + data + trailer)
	ULONG send_size;
} FEED_CONN;

//
// small helpers
//

BOOLEAN _fs_is_file (
	_In_ LPCWSTR path
)
{
	DWORD attrs = GetFileAttributesW (path);

	return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

BOOLEAN _fs_is_directory (
	_In_ LPCWSTR path
)
{
	DWORD attrs = GetFileAttributesW (path);

	return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

//
// read a whole file (used for the PFX blob)
//
PBYTE _fs_read_file (
	_In_ LPCWSTR path,
	_Out_ PULONG size
)
{
	*size = 0;

	HANDLE handle = CreateFileW (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (handle == INVALID_HANDLE_VALUE)
		return NULL;

	LARGE_INTEGER file_size;

	if (!GetFileSizeEx (handle, &file_size) || file_size.QuadPart <= 0 || file_size.QuadPart > 0x10000000)
	{
		CloseHandle (handle);
		return NULL; // empty or > 256 MB: fail-closed
	}

	PBYTE buffer = _r_mem_allocate ((ULONG_PTR)file_size.QuadPart);

	if (!buffer)
	{
		CloseHandle (handle);
		return NULL;
	}

	DWORD read = 0;

	if (!ReadFile (handle, buffer, (DWORD)file_size.QuadPart, &read, NULL) || read != (DWORD)file_size.QuadPart)
	{
		_r_mem_free (buffer);
		CloseHandle (handle);
		return NULL;
	}

	CloseHandle (handle);

	*size = (ULONG)file_size.QuadPart;

	return buffer;
}

//
// narrow/wide helper for the ANSI-only winsock conversion APIs
// (inet_pton takes narrow strings; IP literals are ASCII)
//
VOID _fs_ansi_from_wide (
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

BOOLEAN _fs_send_all (
	_In_ SOCKET sock,
	_In_reads_ (length) const PBYTE buf,
	_In_ INT length
)
{
	INT sent = 0;

	while (sent < length)
	{
		INT sent_now = send (sock, (PCHAR)buf + sent, length - sent, 0);

		if (sent_now == SOCKET_ERROR || sent_now <= 0)
			return FALSE;

		sent += sent_now;
	}

	return TRUE;
}

//
// receive more raw (encrypted) bytes into the connection buffer
//
INT _fs_recv_more (
	_Inout_ FEED_CONN *conn
)
{
	if (conn->raw_len >= conn->raw_size)
		return -1; // buffer full: fail-closed

	INT received = recv (conn->sock, (PCHAR)conn->raw + conn->raw_len, (INT)(conn->raw_size - conn->raw_len), 0);

	if (received > 0)
		conn->raw_len += (ULONG)received;

	return received;
}

//
// TLS handshake (server side): loop AcceptSecurityContext until SEC_E_OK,
// streaming tokens back to the client. left-over (post-ClientFinished)
// bytes stay in conn->raw for the decrypt loop.
//
SECURITY_STATUS _fs_handshake (
	_Inout_ FEED_CONN *conn
)
{
	SECURITY_STATUS status;
	TimeStamp expiry = {0};

	for (;;)
	{
		SecBuffer inbufs[2];
		SecBufferDesc indesc;
		SecBuffer outbuf;
		SecBufferDesc outdesc;
		ULONG attrs = 0;
		ULONG extra = 0;

		// never hand AcceptSecurityContext an empty buffer
		if (conn->raw_len == 0)
		{
			if (_fs_recv_more (conn) <= 0)
				return SEC_E_INTERNAL_ERROR;
		}

		ULONG pre_call_bytes = conn->raw_len;

		inbufs[0].cbBuffer = conn->raw_len;
		inbufs[0].BufferType = SECBUFFER_TOKEN;
		inbufs[0].pvBuffer = conn->raw;
		inbufs[1].cbBuffer = 0;
		inbufs[1].BufferType = SECBUFFER_EMPTY;
		inbufs[1].pvBuffer = NULL;

		indesc.ulVersion = SECBUFFER_VERSION;
		indesc.cBuffers = 2;
		indesc.pBuffers = inbufs;

		outbuf.cbBuffer = 0;
		outbuf.BufferType = SECBUFFER_TOKEN;
		outbuf.pvBuffer = NULL;

		outdesc.ulVersion = SECBUFFER_VERSION;
		outdesc.cBuffers = 1;
		outdesc.pBuffers = &outbuf;

		status = AcceptSecurityContext (
			&conn->cred,
			conn->have_ctx ? &conn->ctx : NULL,
			&indesc,
			ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
			ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM | ASC_REQ_EXTENDED_ERROR,
			SECURITY_NATIVE_DREP,
			&conn->ctx,
			&outdesc,
			&attrs,
			&expiry
		);

		conn->have_ctx = TRUE;

		// stream any handshake token back to the client
		if (outbuf.cbBuffer && outbuf.pvBuffer)
		{
			BOOLEAN sent = _fs_send_all (conn->sock, outbuf.pvBuffer, (INT)outbuf.cbBuffer);
			FreeContextBuffer (outbuf.pvBuffer);

			if (!sent)
				return SEC_E_INTERNAL_ERROR;
		}

		// consume consumed input; keep SECBUFFER_EXTRA
		for (ULONG i = 0; i < indesc.cBuffers; i++)
		{
			if (inbufs[i].BufferType == SECBUFFER_EXTRA && inbufs[i].cbBuffer)
				extra = inbufs[i].cbBuffer;
		}

		if (extra)
		{
			memmove (conn->raw, conn->raw + (conn->raw_len - extra), extra);
			conn->raw_len = extra;
		}
		else if (status != SEC_E_INCOMPLETE_MESSAGE)
		{
			conn->raw_len = 0;
		}

		if (status == SEC_E_OK)
			break;

		if (status == SEC_E_INCOMPLETE_MESSAGE || status == SEC_I_CONTINUE_NEEDED || status == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			if (_fs_recv_more (conn) <= 0)
				return SEC_E_INTERNAL_ERROR;

			continue;
		}

		_r_console_writestringformat (L"feedserver: AcceptSecurityContext failed: 0x%08X (input bytes at call: %lu)\n", (ULONG)status, pre_call_bytes);

		return status; // hard handshake failure
	}

	// stream sizes for the encrypt/decrypt loops
	return QueryContextAttributes (&conn->ctx, SECPKG_ATTR_STREAM_SIZES, &conn->sizes);
}

//
// decrypt one step: append decrypted plaintext to the caller buffer,
// keep SECBUFFER_EXTRA (still-encrypted remainder) in conn->raw.
//
SECURITY_STATUS _fs_decrypt_step (
	_Inout_ FEED_CONN *conn,
	_Out_writes_bytes_ (plain_size) PBYTE plain,
	_In_ ULONG plain_size,
	_Inout_ PULONG plain_len
)
{
	SecBuffer bufs[4];
	SecBufferDesc desc;
	SECURITY_STATUS status;
	ULONG extra = 0;

	bufs[0].cbBuffer = conn->raw_len;
	bufs[0].BufferType = SECBUFFER_DATA;
	bufs[0].pvBuffer = conn->raw;

	for (ULONG i = 1; i < RTL_NUMBER_OF (bufs); i++)
	{
		bufs[i].cbBuffer = 0;
		bufs[i].BufferType = SECBUFFER_EMPTY;
		bufs[i].pvBuffer = NULL;
	}

	desc.ulVersion = SECBUFFER_VERSION;
	desc.cBuffers = 4;
	desc.pBuffers = bufs;

	status = DecryptMessage (&conn->ctx, &desc, 0, NULL);

	if (status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED)
	{
		for (ULONG i = 0; i < desc.cBuffers; i++)
		{
			if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer)
			{
				ULONG space = plain_size - *plain_len;
				ULONG copy = bufs[i].cbBuffer < space ? bufs[i].cbBuffer : space;

				memcpy (plain + *plain_len, bufs[i].pvBuffer, copy);
				*plain_len += copy;
			}
			else if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].cbBuffer)
			{
				extra = bufs[i].cbBuffer;
			}
		}

		if (extra)
			memmove (conn->raw, conn->raw + (conn->raw_len - extra), extra);

		conn->raw_len = extra;
	}
	else if (status == SEC_I_RENEGOTIATE)
	{
		// fail-closed: the rig does not renegotiate mid-request
		conn->raw_len = 0;
	}

	return status;
}

//
// encrypt+send the response payload in schannel-sized chunks
//
BOOLEAN _fs_encrypt_send (
	_Inout_ FEED_CONN *conn,
	_In_reads_bytes_ (length) const BYTE *data,
	_In_ ULONG length
)
{
	if (!conn->send)
		return FALSE;

	while (length)
	{
		ULONG chunk = length < conn->sizes.cbMaximumMessage ? length : conn->sizes.cbMaximumMessage;
		SecBuffer bufs[4];
		SecBufferDesc desc;
		SECURITY_STATUS status;
		ULONG total;

		bufs[0].cbBuffer = conn->sizes.cbHeader;
		bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
		bufs[0].pvBuffer = conn->send;
		bufs[1].cbBuffer = chunk;
		bufs[1].BufferType = SECBUFFER_DATA;
		bufs[1].pvBuffer = conn->send + conn->sizes.cbHeader;
		bufs[2].cbBuffer = conn->sizes.cbTrailer;
		bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
		bufs[2].pvBuffer = conn->send + conn->sizes.cbHeader + chunk;
		bufs[3].cbBuffer = 0;
		bufs[3].BufferType = SECBUFFER_EMPTY;
		bufs[3].pvBuffer = NULL;

		desc.ulVersion = SECBUFFER_VERSION;
		desc.cBuffers = 4;
		desc.pBuffers = bufs;

		memcpy (bufs[1].pvBuffer, data, chunk);

		status = EncryptMessage (&conn->ctx, 0, &desc, conn->seqno++);

		if (FAILED (status))
			return FALSE;

		total = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;

		if (!_fs_send_all (conn->sock, conn->send, (INT)total))
			return FALSE;

		data += chunk;
		length -= chunk;
	}

	return TRUE;
}

//
// send the response header block (HTTP/1.1, Connection: close)
//
BOOLEAN _fs_send_headers (
	_Inout_ FEED_CONN *conn,
	_In_ UINT status,
	_In_ LPCSTR reason,
	_In_ LPCSTR content_type,
	_In_ ULONGLONG length
)
{
	CHAR header[512];
	INT header_len;

	header_len = sprintf_s (header, sizeof (header),
		"HTTP/1.1 %u %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %I64u\r\n"
		"Connection: close\r\n"
		"\r\n",
		status, reason, content_type, length
	);

	if (header_len <= 0)
		return FALSE;

	return _fs_encrypt_send (conn, (PBYTE)header, (ULONG)header_len);
}

//
// send a small plain-text error body
//
BOOLEAN _fs_send_error (
	_Inout_ FEED_CONN *conn,
	_In_ UINT status,
	_In_ LPCSTR reason,
	_In_ LPCSTR body_text
)
{
	ULONG body_len = (ULONG)strlen (body_text);

	if (!_fs_send_headers (conn, status, reason, "text/plain", body_len))
		return FALSE;

	return _fs_encrypt_send (conn, (PBYTE)body_text, body_len);
}

//
// stream a file as the 200 response body
//
BOOLEAN _fs_serve_file (
	_Inout_ FEED_CONN *conn,
	_In_ LPCWSTR path
)
{
	HANDLE handle = CreateFileW (path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (handle == INVALID_HANDLE_VALUE)
		return FALSE; // caller sends 404 (does not leak the error kind)

	LARGE_INTEGER file_size;

	if (!GetFileSizeEx (handle, &file_size) || file_size.QuadPart < 0)
	{
		CloseHandle (handle);
		return FALSE;
	}

	// content-type by extension: text/plain for VERSION/VERSION.sig/.txt,
	// application/octet-stream default (parity with the brief; the python
	// version guessed by extension the same way)
	LPCWSTR base_name = wcsrchr (path, L'\\');
	LPCSTR content_type = "application/octet-stream";

	base_name = base_name ? base_name + 1 : path;

	ULONG_PTR base_len = _r_str_getlength (base_name);

	if (_wcsicmp (base_name, L"VERSION") == 0 || _wcsicmp (base_name, L"VERSION.sig") == 0 ||
		(base_len >= 4 && _wcsicmp (base_name + base_len - 4, L".txt") == 0))
	{
		content_type = "text/plain";
	}

	if (!_fs_send_headers (conn, 200, "OK", content_type, (ULONGLONG)file_size.QuadPart))
	{
		CloseHandle (handle);
		return FALSE;
	}

	PBYTE chunk = _r_mem_allocate (conn->sizes.cbMaximumMessage);
	BOOLEAN sent = FALSE;

	if (chunk)
	{
		sent = TRUE;
		LONGLONG remaining = file_size.QuadPart;

		while (remaining > 0)
		{
			ULONG want = remaining < (LONGLONG)conn->sizes.cbMaximumMessage ? (ULONG)remaining : conn->sizes.cbMaximumMessage;
			DWORD read = 0;

			if (!ReadFile (handle, chunk, want, &read, NULL) || !read)
			{
				sent = FALSE; // short read mid-response: abort the body
				break;
			}

			if (!_fs_encrypt_send (conn, chunk, read))
			{
				sent = FALSE;
				break;
			}

			remaining -= (LONGLONG)read;
		}

		_r_mem_free (chunk);
	}

	CloseHandle (handle);

	return sent;
}

//
// percent-decode a request target (minimal: %XX only; '+' is NOT space
// in paths)
//
BOOLEAN _fs_url_decode (
	_In_ LPCWSTR source,
	_Out_writes_ (dst_size) LPWSTR dst,
	_In_ ULONG dst_size
)
{
	ULONG out = 0;

	for (ULONG i = 0; source[i]; i++)
	{
		WCHAR ch = source[i];

		if (out + 1 >= dst_size)
			return FALSE;

		if (ch == L'%' && source[i + 1] && source[i + 2])
		{
			WCHAR hex[3] = {source[i + 1], source[i + 2], UNICODE_NULL};
			LPWSTR end = NULL;
			ULONG value = wcstoul (hex, &end, 16);

			if (end != hex + 2)
				return FALSE; // invalid escape: fail-closed

			dst[out++] = (WCHAR)value;
			i += 2;
			continue;
		}

		dst[out++] = ch;
	}

	dst[out] = UNICODE_NULL;

	return TRUE;
}

//
// normalize the request target into an absolute path under the root.
// returns FALSE for anything refused (traversal, listing, invalid) —
// *is_denied tells the caller to answer 403 instead of 404.
//
BOOLEAN _fs_map_path (
	_In_ LPCWSTR root,
	_In_ LPCWSTR target,
	_Out_writes_ (local_size) LPWSTR local,
	_In_ ULONG local_size,
	_Out_ PBOOLEAN is_denied
)
{
	WCHAR decoded[FEED_REL_MAX];
	WCHAR rel[FEED_REL_MAX];
	ULONG marks[FEED_DEPTH_MAX];
	ULONG mark_count = 0;
	ULONG rpos = 0;
	ULONG i = 0;

	*is_denied = FALSE;

	// strip the query string
	ULONG target_len = (ULONG)_r_str_getlength (target);
	WCHAR clean[FEED_TARGET_MAX];

	for (i = 0; i < target_len && i < RTL_NUMBER_OF (clean) - 1; i++)
	{
		if (target[i] == L'?')
			break;

		clean[i] = target[i];
	}

	clean[i] = UNICODE_NULL;

	if (!_fs_url_decode (clean, decoded, RTL_NUMBER_OF (decoded)))
	{
		*is_denied = TRUE;
		return FALSE;
	}

	// split on separators; skip "" and "."; ".." pops (refused past the
	// root); every other segment is kept verbatim
	i = 0;

	for (;;)
	{
		ULONG start = i;

		while (decoded[i] && decoded[i] != L'/' && decoded[i] != L'\\')
			i++;

		ULONG len = i - start;

		if (len && !(len == 1 && decoded[start] == L'.'))
		{
			if (len == 2 && decoded[start] == L'.' && decoded[start + 1] == L'.')
			{
				if (!mark_count)
				{
					*is_denied = TRUE; // traversal above the root: refused
					return FALSE;
				}

				mark_count--;
				rpos = marks[mark_count];
			}
			else
			{
				if (mark_count >= FEED_DEPTH_MAX || rpos + len + 2 >= RTL_NUMBER_OF (rel))
				{
					*is_denied = TRUE;
					return FALSE;
				}

				for (ULONG j = start; j < start + len; j++)
				{
					// ':' would introduce drive/ADS syntax; refuse it outright
					if (decoded[j] == L':')
					{
						*is_denied = TRUE;
						return FALSE;
					}
				}

				if (rpos && rel[rpos - 1] != L'\\')
					rel[rpos++] = L'\\';

				marks[mark_count++] = rpos;

				memcpy (rel + rpos, decoded + start, len * sizeof (WCHAR));
				rpos += len;
			}
		}

		if (!decoded[i])
			break;

		i++; // skip the separator
	}

	if (!mark_count)
	{
		*is_denied = TRUE; // empty path: directory-listing attempt
		return FALSE;
	}

	rel[rpos] = UNICODE_NULL;

	INT written = swprintf (local, local_size, L"%s\\%s", root, rel);

	return written > 0 && (ULONG)written < local_size;
}

//
// read one request (decrypt until the end-of-headers marker appears)
//
BOOLEAN _fs_read_request (
	_Inout_ FEED_CONN *conn,
	_Out_writes_bytes_ (plain_size) PBYTE plain,
	_In_ ULONG plain_size,
	_Out_ PULONG plain_len
)
{
	*plain_len = 0;

	for (;;)
	{
		for (ULONG i = 0; i + 3 < *plain_len; i++)
		{
			if (plain[i] == '\r' && plain[i + 1] == '\n' && plain[i + 2] == '\r' && plain[i + 3] == '\n')
				return TRUE;
		}

		if (*plain_len + 4 >= plain_size)
			return FALSE; // oversized headers: fail-closed

		SECURITY_STATUS status = _fs_decrypt_step (conn, plain, plain_size, plain_len);

		if (status == SEC_E_OK)
		{
			if (*plain_len || conn->raw_len)
				continue; // more plaintext may follow; keep scanning

			if (_fs_recv_more (conn) <= 0)
				return FALSE;

			continue;
		}

		if (status == SEC_E_INCOMPLETE_MESSAGE)
		{
			if (_fs_recv_more (conn) <= 0)
				return FALSE;

			continue;
		}

		return FALSE; // decrypt error / expired / renegotiate: fail-closed
	}
}

//
// per-connection handler: TLS handshake, one GET, response, log
//
VOID _fs_handle_connection (
	_In_ FEED_SERVER *srv,
	_In_ SOCKET sock,
	_In_ SOCKADDR_IN *peer
)
{
	FEED_CONN conn = {0};
	SECURITY_STATUS status;
	PBYTE plain = NULL;
	CHAR peer_a[64];
	WCHAR peer_w[64];
	WCHAR date[40];
	WCHAR request_w[1024];

	// every TLS operation of this connection runs under the server credential
	conn.cred = srv->cred;

	conn.sock = sock;
	conn.raw_size = FEED_RAW_SIZE;
	conn.raw = _r_mem_allocate (conn.raw_size);

	if (!conn.raw)
		return;

	// per-socket timeouts: a wedged client must not stall the sequential
	// accept loop (fail-closed)
	DWORD timeout = FEED_TIMEOUT_MS;
	setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&timeout, sizeof (timeout));
	setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (PCHAR)&timeout, sizeof (timeout));

	status = _fs_handshake (&conn);

	if (FAILED (status))
	{
		if (!inet_ntop (AF_INET, &peer->sin_addr, peer_a, RTL_NUMBER_OF (peer_a)))
			strcpy_s (peer_a, sizeof (peer_a), "?");

		_r_console_writestringformat (L"feedserver: handshake failed from %S: 0x%08X\n", peer_a, (ULONG)status);

		if (conn.have_ctx)
			DeleteSecurityContext (&conn.ctx);

		_r_mem_free (conn.raw);
		return;
	}

	// plaintext staging + encrypted send staging
	conn.send_size = (ULONG)conn.sizes.cbHeader + conn.sizes.cbMaximumMessage + conn.sizes.cbTrailer;
	conn.send = _r_mem_allocate (conn.send_size);
	plain = _r_mem_allocate (FEED_PLAIN_SIZE);

	if (!conn.send || !plain)
	{
		if (conn.have_ctx)
			DeleteSecurityContext (&conn.ctx);

		if (conn.send)
			_r_mem_free (conn.send);

		if (plain)
			_r_mem_free (plain);

		_r_mem_free (conn.raw);
		return;
	}

	ULONG plain_len = 0;

	if (_fs_read_request (&conn, plain, FEED_PLAIN_SIZE, &plain_len))
	{
		CHAR request_line[1024] = {0};
		CHAR method[16] = {0};
		CHAR target[FEED_TARGET_MAX] = {0};
		WCHAR target_w[FEED_TARGET_MAX];
		WCHAR local[MAX_PATH + 32];
		UINT status_code = 400;
		ULONG i;

		// first line only
		for (i = 0; i < plain_len && i < RTL_NUMBER_OF (request_line) - 1; i++)
		{
			if (plain[i] == '\r' || plain[i] == '\n')
				break;

			request_line[i] = (CHAR)plain[i];
		}

		request_line[i] = '\0';

		// "GET <target> HTTP/1.x"
		if (sscanf_s (request_line, "%15s %511s", method, (UINT)sizeof (method), target, (UINT)sizeof (target)) >= 2)
		{
			for (i = 0; request_line[i]; i++)
				request_w[i] = (WCHAR)(BYTE)request_line[i];

			request_w[i] = UNICODE_NULL;

			for (i = 0; target[i]; i++)
				target_w[i] = (WCHAR)(BYTE)target[i];

			target_w[i] = UNICODE_NULL;

			BOOLEAN denied = FALSE;

			if (strcmp (method, "GET") != 0)
			{
				// python: do_GET only -> 501
				status_code = 501;
				_fs_send_error (&conn, 501, "Unsupported method", "Unsupported method\n");
			}
			else if (_fs_map_path (srv->root, target_w, local, RTL_NUMBER_OF (local), &denied) && !denied)
			{
				if (_fs_is_directory (local))
				{
					// DEC-04/SEC-02 posture: the rig environment must not
					// expose an index (C rig: 403 per the acceptance
					// criteria; python sent 404 with the same text)
					status_code = 403;
					_fs_send_error (&conn, 403, "Forbidden", "Directory listing forbidden\n");
				}
				else if (_fs_serve_file (&conn, local))
				{
					status_code = 200;
				}
				else
				{
					// missing (or unreadable) -> 404, no error kind leaked
					status_code = 404;
					_fs_send_error (&conn, 404, "Not Found", "Not Found\n");
				}
			}
			else
			{
				// traversal above the root / listing / unparseable: refused
				status_code = 403;
				_fs_send_error (&conn, 403, "Forbidden", "Directory listing forbidden\n");
			}
		}
		else
		{
			request_line[RTL_NUMBER_OF (request_line) - 1] = '\0';

			for (i = 0; request_line[i]; i++)
				request_w[i] = (WCHAR)(BYTE)request_line[i];

			request_w[i] = UNICODE_NULL;

			status_code = 400;
			_fs_send_error (&conn, 400, "Bad Request", "Bad Request\n");
		}

		// request log (python BaseHTTPRequestHandler.log_message shape)
		if (!inet_ntop (AF_INET, &peer->sin_addr, peer_a, RTL_NUMBER_OF (peer_a)))
			strcpy_s (peer_a, sizeof (peer_a), "?");

		for (i = 0; peer_a[i] && i < RTL_NUMBER_OF (peer_w) - 1; i++)
			peer_w[i] = (WCHAR)(BYTE)peer_a[i];

		peer_w[i] = UNICODE_NULL;

		SYSTEMTIME st = {0};
		GetLocalTime (&st);

		static const WCHAR *months[12] = {L"Jan", L"Feb", L"Mar", L"Apr", L"May", L"Jun", L"Jul", L"Aug", L"Sep", L"Oct", L"Nov", L"Dec"};

		swprintf (date, RTL_NUMBER_OF (date), L"%02u/%s/%04u %02u:%02u:%02u",
			(unsigned)st.wDay, months[st.wMonth - 1], (unsigned)st.wYear,
			(unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);

		_r_console_writestringformat (L"%s - - [%s] \"%s\" %u -\n", peer_w, date, request_w, status_code);
	}
	else
	{
		if (!inet_ntop (AF_INET, &peer->sin_addr, peer_a, RTL_NUMBER_OF (peer_a)))
			strcpy_s (peer_a, sizeof (peer_a), "?");

		_r_console_writestringformat (L"feedserver: request read failed from %S (tls state 0x%08X)\n", peer_a, (ULONG)status);
	}

	if (conn.have_ctx)
		DeleteSecurityContext (&conn.ctx);

	if (conn.send)
		_r_mem_free (conn.send);

	if (plain)
		_r_mem_free (plain);

	_r_mem_free (conn.raw);
}

//
// PFX import + schannel credentials (approved simplification: PFX only)
//
BOOLEAN _fs_load_certificate (
	_Inout_ FEED_SERVER *srv,
	_In_ LPCWSTR pfx_path,
	_In_ LPCWSTR password
)
{
	ULONG size = 0;
	PBYTE blob_data = _fs_read_file (pfx_path, &size);

	if (!blob_data)
	{
		_r_console_writestringformat (L"FAIL: cannot read PFX file: %s\n", pfx_path);
		return FALSE;
	}

	CRYPT_DATA_BLOB blob;
	blob.cbData = size;
	blob.pbData = blob_data;

	// in-memory import (no CRYPT_USER_KEYSET): the key becomes an EPHEMERAL
	// CNG key (lsass-backed handle), the same shape .NET SslStream produces
	// from a PFX; the handle is attached to the cert context below
	HCERTSTORE store = PFXImportCertStore (&blob, password, 0);

	if (!store)
	{
		_r_console_writestringformat (L"FAIL: cannot import PFX '%s' (wrong password or corrupt file; error 0x%08X)\n", pfx_path, (ULONG)GetLastError ());
		_r_mem_free (blob_data);
		return FALSE;
	}

	PCCERT_CONTEXT cert = CertFindCertificateInStore (store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);

	if (!cert)
	{
		_r_console_writestringformat (L"FAIL: no certificate in PFX '%s'\n", pfx_path);
		CertCloseStore (store, 0);
		_r_mem_free (blob_data);
		return FALSE;
	}

	srv->store = store; // keep the PFX store open for the process lifetime
	_r_mem_free (blob_data);

	// open the private key and ATTACH it to the cert context via
	// CERT_KEY_CONTEXT: lsass-side schannel resolves keys by HANDLE —
	// re-resolving by CERT_KEY_PROV_INFO against a user-profile key fails
	// on VBS/Credential-Guard machines with SEC_E_NO_AUTHENTICATING_AUTHORITY
	// (the same PFX works when the handle travels with the context, which is
	// how .NET SslStream loads PFX certificates). The handle stays open for
	// the process lifetime.
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key_handle = 0;
	DWORD key_spec = 0;
	BOOL free_key = FALSE;

	if (!CryptAcquireCertificatePrivateKey (cert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &key_handle, &key_spec, &free_key))
	{
		_r_console_writestringformat (L"FAIL: the PFX private key is not usable (error 0x%08X)\n", (ULONG)GetLastError ());
		CertFreeCertificateContext (cert);
		CertCloseStore (store, 0);
		_r_mem_free (blob_data);
		return FALSE;
	}

	srv->key_handle = key_handle;
	srv->cert = CertDuplicateCertificateContext (cert);
	CertFreeCertificateContext (cert);

	if (!srv->cert)
	{
		_r_console_writestringformat (L"FAIL: cannot keep the PFX certificate context\n");
		return FALSE;
	}

	// attach the key handle to the FINAL context (CertDuplicateCertificateContext
	// does not carry context properties over)
	CERT_KEY_CONTEXT key_context;
	key_context.cbSize = sizeof (key_context);
	key_context.hCryptProv = (HCRYPTPROV)key_handle; // NCRYPT handle (key_spec = CERT_NCRYPT_KEY_SPEC)
	key_context.dwKeySpec = key_spec;
	CertSetCertificateContextProperty (srv->cert, CERT_KEY_CONTEXT_PROP_ID, 0, &key_context);

	// SCH_CREDENTIALS (modern credential struct, UNICODE_STRING provided by
	// subauth.h above): the legacy SCHANNEL_CRED path fails every handshake
	// with SEC_E_NO_AUTHENTICATING_AUTHORITY on current OS builds, while the
	// modern path negotiates TLS 1.2/1.3 like the python rig's ssl module
	SCH_CREDENTIALS creds = {0};
	creds.dwVersion = SCH_CREDENTIALS_VERSION;
	creds.cCreds = 1;
	creds.paCred = &srv->cert;
	creds.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;

	TimeStamp expiry = {0};
	SECURITY_STATUS status = AcquireCredentialsHandleW (NULL, UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &creds, NULL, NULL, &srv->cred, &expiry);

	if (status != SEC_E_OK)
	{
		_r_console_writestringformat (L"FAIL: AcquireCredentialsHandle failed: 0x%08X\n", (ULONG)status);
		return FALSE;
	}

	srv->have_cred = TRUE;

	return TRUE;
}

//
// entry (DEC-10): wmain + APP_CONSOLE bootstrap
//
INT wmain (
	_In_ INT argc,
	_In_ WCHAR **argv
)
{
	WSADATA wsa = {0};
	FEED_SERVER srv = {0};
	SOCKADDR_IN local = {0};
	SOCKET lsock;
	WCHAR root[MAX_PATH + 32];
	PR_STRING root_value = NULL;
	PR_STRING pfx_value = NULL;
	PR_STRING password_value = NULL;
	PR_STRING port_value = NULL;
	PR_STRING bind_value = NULL;
	ULONG port = 443;

	UNREFERENCED_PARAMETER (argc);
	UNREFERENCED_PARAMETER (argv);

	if (!_r_app_initialize (NULL))
		return ERROR_APP_INIT_FAILURE;

	// required options (python: --root --cert --key; C: --root --pfx --password)
	if (!_r_sys_getopt (_r_sys_getcommandline (), L"root", &root_value) || !root_value || _r_obj_isstringempty2 (&root_value->sr))
		goto usage;

	if (!_r_sys_getopt (_r_sys_getcommandline (), L"pfx", &pfx_value) || !pfx_value || _r_obj_isstringempty2 (&pfx_value->sr))
		goto usage;

	if (!_r_sys_getopt (_r_sys_getcommandline (), L"password", &password_value) || !password_value || _r_obj_isstringempty2 (&password_value->sr))
		goto usage;

	_r_sys_getopt (_r_sys_getcommandline (), L"port", &port_value);
	_r_sys_getopt (_r_sys_getcommandline (), L"bind", &bind_value);

	if (port_value && !_r_obj_isstringempty2 (&port_value->sr))
	{
		port = wcstoul (port_value->buffer, NULL, 10);

		if (!port || port > 65535)
		{
			_r_console_writestringformat (L"FAIL: invalid port: %s\n", port_value->buffer);
			return 1;
		}
	}

	// resolve the root to an absolute path (python: os.path.abspath)
	if (!GetFullPathNameW (root_value->buffer, (DWORD)RTL_NUMBER_OF (root), root, NULL))
	{
		_r_console_writestringformat (L"FAIL: feed root missing: %s\n", root_value->buffer);
		return 1;
	}

	// fail-closed checks (python main() order, SEC-02/AS13)
	if (GetFileAttributesW (root) == INVALID_FILE_ATTRIBUTES || !_fs_is_directory (root))
	{
		_r_console_writestringformat (L"FAIL: feed root missing: %s\n", root);
		return 1;
	}

	WCHAR check_path[MAX_PATH + 64];

	swprintf (check_path, RTL_NUMBER_OF (check_path), L"%s\\%s", root, L"VERSION");

	if (!_fs_is_file (check_path))
	{
		_r_console_writestringformat (L"FAIL: feed root lacks VERSION — the harness is meaningless without the feed pair (fail-closed)\n");
		return 1;
	}

	swprintf (check_path, RTL_NUMBER_OF (check_path), L"%s\\%s", root, L"VERSION.sig");

	if (!_fs_is_file (check_path))
	{
		_r_console_writestringformat (L"FAIL: feed root lacks VERSION.sig — the harness is meaningless without the feed pair (fail-closed)\n");
		return 1;
	}

	if (!_fs_is_file (pfx_value->buffer))
	{
		_r_console_writestringformat (L"FAIL: TLS file missing: %s\n", pfx_value->buffer);
		return 1;
	}

	if (WSAStartup (MAKEWORD (2, 2), &wsa) != 0)
	{
		_r_console_writestringformat (L"FAIL: WSAStartup failed (wsa error %lu)\n", (ULONG)WSAGetLastError ());
		return 1;
	}

	if (!_fs_load_certificate (&srv, pfx_value->buffer, password_value->buffer))
	{
		WSACleanup ();
		return 1;
	}

	srv.root = root;

	CHAR bind_a[64];

	if (bind_value && !_r_obj_isstringempty2 (&bind_value->sr))
	{
		_fs_ansi_from_wide (bind_value->buffer, bind_a, (ULONG)sizeof (bind_a));

		if (inet_pton (AF_INET, bind_a, &local.sin_addr) != 1)
		{
			_r_console_writestringformat (L"FAIL: invalid bind address: %s\n", bind_value->buffer);
			WSACleanup ();
			return 1;
		}
	}
	else
	{
		if (inet_pton (AF_INET, "127.0.0.1", &local.sin_addr) != 1)
		{
			_r_console_writestringformat (L"FAIL: cannot parse the default bind address\n");
			WSACleanup ();
			return 1;
		}
	}

	local.sin_family = AF_INET;
	local.sin_port = htons ((USHORT)port);

	lsock = WSASocketW (AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

	if (lsock == INVALID_SOCKET)
	{
		_r_console_writestringformat (L"FAIL: cannot create the listen socket (wsa error %lu)\n", (ULONG)WSAGetLastError ());
		WSACleanup ();
		return 1;
	}

	BOOL reuse = TRUE; // python http.server allow_reuse_address parity
	setsockopt (lsock, SOL_SOCKET, SO_REUSEADDR, (PCHAR)&reuse, sizeof (reuse));

	if (bind (lsock, (PSOCKADDR)&local, sizeof (local)) == SOCKET_ERROR)
	{
		_r_console_writestringformat (L"FAIL: cannot bind https://%s:%u (wsa error %lu)\n", bind_value ? bind_value->buffer : L"127.0.0.1", port, (ULONG)WSAGetLastError ());
		closesocket (lsock);
		WSACleanup ();
		return 1;
	}

	if (listen (lsock, FEED_BACKLOG) == SOCKET_ERROR)
	{
		_r_console_writestringformat (L"FAIL: cannot listen (wsa error %lu)\n", (ULONG)WSAGetLastError ());
		closesocket (lsock);
		WSACleanup ();
		return 1;
	}

	_r_console_writestringformat (L"feedserver: https://%s:%u root=%s (Ctrl+C to stop)\n",
		bind_value && !_r_obj_isstringempty2 (&bind_value->sr) ? bind_value->buffer : L"127.0.0.1",
		port, srv.root);

	// sequential accept loop (brief-approved for a test rig)
	for (;;)
	{
		SOCKADDR_IN peer = {0};
		INT peer_length = sizeof (peer);

		SOCKET csock = accept (lsock, (PSOCKADDR)&peer, &peer_length);

		if (csock == INVALID_SOCKET)
			continue;

		_fs_handle_connection (&srv, csock, &peer);

		closesocket (csock);
	}

	// unreachable: the rig stops with Ctrl+C
	FreeCredentialsHandle (&srv.cred);
	CertFreeCertificateContext (srv.cert);
	WSACleanup ();

	return 0;

usage:
	_r_console_writestringformat (L"usage: feedserver --root <feed-dir> --pfx <file.pfx> --password <pass> [--port 443] [--bind 127.0.0.1]\n");
	return 2; // argparse-style usage error (python ap.error exit code)
}
